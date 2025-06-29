/*
 *
 * Copyright (c) 2025 WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.wso2.apim.policies.mediation.ai.integration.guardrail;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONObject;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Integration Guardrail mediator.
 * <p>
 * A mediator that integrates with an external webhook to validate API payloads (requests or responses)
 * against custom logic or policies defined outside the gateway.
 * <p>
 * Sends the extracted payload to a webhook URL via HTTP POST and interprets the webhook's verdict.
 * If a payload violation is detected, detailed error information is populated into the message context,
 * and an optional fault sequence can be invoked to handle the violation gracefully.
 */
public class IntegrationGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(IntegrationGuardrail.class);

    private String name;
    private String webhookUrl;
    private String headers;
    private String jsonPath = "";
    private int timeout = 60000;

    /**
     * Initializes the IntegrationGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("IntegrationGuardrail: Initialized.");
        }
    }

    /**
     * Destroys the IntegrationGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    /**
     * Executes the IntegrationGuardrail mediation logic.
     * <p>
     * Validates the payload by sending it to the configured webhook. If the webhook indicates a violation,
     * the mediator sets appropriate error properties and triggers a fault sequence if configured.
     *
     * @param messageContext The message context containing the payload to validate.
     * @return {@code true} if mediation should continue, {@code false} if processing should halt.
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Executing IntegrationGuardrail mediation.");
        }

        try {
            Optional<String> validationResult = validatePayload(messageContext);
            if (validationResult.isPresent()) {
                setErrorProperties(messageContext, validationResult.get());
                if (logger.isDebugEnabled()) {
                    logger.debug("Triggering IntegrationGuardrail fault sequence.");
                }
                Mediator faultMediator = messageContext.getSequence(IntegrationGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false;
            }
        } catch (Exception e) {
            logger.error("Error during IntegrationGuardrail mediation", e);
        }

        return true;
    }

    private Optional<String> validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating payload via IntegrationGuardrail.");
        }

        Map<String, Object> metadata = new HashMap<>();
        String jsonPayload = extractJsonContent(messageContext);

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath != null && !this.jsonPath.trim().isEmpty()) {
            jsonPayload = JsonPath.read(jsonPayload, this.jsonPath).toString();
        }

        // Remove quotes at beginning and end
        jsonPayload = jsonPayload.replaceAll("^\"|\"$", "").trim();

        if (!messageContext.isResponse()) {
            metadata.put(IntegrationGuardrailConstants.REQUEST_PAYLOAD_KEY, jsonPayload);
        } else {
            metadata.put(IntegrationGuardrailConstants.RESPONSE_PAYLOAD_KEY, jsonPayload);
        }

        try {
            String webhookResponse = sendPostRequestToWebhook(metadata);
            JSONObject responseJson = new JSONObject(webhookResponse);
            String action = determineAssessmentAction(responseJson);

            if ("GUARDRAIL_INTERVENED".equals(action)) {
                return Optional.of(buildAssessment(responseJson));
            }

        } catch (Exception e) {
            logger.error("Error sending POST request to webhook.", e);
        }

        return Optional.empty(); // Treat as valid on exception
    }

    private void setErrorProperties(MessageContext messageContext, String assessmentJson) {
        messageContext.setProperty(SynapseConstants.ERROR_CODE, IntegrationGuardrailConstants.ERROR_CODE);
        messageContext.setProperty(IntegrationGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
        messageContext.setProperty(IntegrationGuardrailConstants.CUSTOM_HTTP_SC, IntegrationGuardrailConstants.ERROR_CODE);
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentJson);
    }

    private String sendPostRequestToWebhook(Map<String, Object> metadata) throws IOException {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(timeout)
                .setSocketTimeout(timeout)
                .setConnectionRequestTimeout(timeout)
                .build();

        try (CloseableHttpClient httpClient = HttpClients.custom().setDefaultRequestConfig(requestConfig).build()) {
            HttpPost httpPost = new HttpPost(webhookUrl);
            httpPost.setHeader(IntegrationGuardrailConstants.CONTENT_TYPE_HEADER, "application/json");

            if (headers != null && !headers.isEmpty()) {
                Map<String, String> customHeaders = new Gson().fromJson(headers, new TypeToken<Map<String, String>>() {}.getType());
                for (Map.Entry<String, String> header : customHeaders.entrySet()) {
                    if (header.getKey() != null && header.getValue() != null) {
                        httpPost.setHeader(header.getKey(), header.getValue());
                    }
                }
            }

            StringEntity entity = new StringEntity(new Gson().toJson(metadata), StandardCharsets.UTF_8);
            httpPost.setEntity(entity);

            if (logger.isDebugEnabled()) {
                logger.debug("Sending webhook request.");
            }

            HttpResponse response = httpClient.execute(httpPost);
            int statusCode = response.getStatusLine().getStatusCode();
            String responseBody = EntityUtils.toString(response.getEntity());

            if (statusCode == HttpURLConnection.HTTP_OK) {
                return responseBody;
            } else {
                logger.debug("Webhook returned status " + statusCode + ": " + responseBody);
                return "";
            }
        }
    }

    private String determineAssessmentAction(JSONObject responseJson) {
        if (responseJson.has(IntegrationGuardrailConstants.VERDICT)) {
            return responseJson.getBoolean(IntegrationGuardrailConstants.VERDICT) ? "None" : "GUARDRAIL_INTERVENED";
        } else {
            logger.error("Malformed webhook response: missing 'verdict' field. Response: " + responseJson);
            return "None";
        }
    }

    private String buildAssessment(JSONObject responseJson) {
        JSONObject assessment = new JSONObject();

        if (responseJson.has(IntegrationGuardrailConstants.VERDICT)
                && !responseJson.getBoolean(IntegrationGuardrailConstants.VERDICT)) {
            assessment.put(IntegrationGuardrailConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
            assessment.put(IntegrationGuardrailConstants.INTERVENING_GUARDRAIL, this.getName());
            assessment.put(IntegrationGuardrailConstants.ASSESSMENT_REASON, "Guardrail blocked.");
            assessment.put(IntegrationGuardrailConstants.ASSESSMENTS,
                    responseJson.has(IntegrationGuardrailConstants.ASSESSMENTS)
                            ? responseJson.get(IntegrationGuardrailConstants.ASSESSMENTS) :
                            "Violation of " + this.getName() + " detected.");
        } else {
            assessment.put(IntegrationGuardrailConstants.ASSESSMENT_ACTION, "None");
        }

        return assessment.toString();
    }

    /**
     * Extracts JSON content from the message context.
     * This utility method converts the Axis2 message payload to a JSON string.
     *
     * @param messageContext The message context containing the JSON payload
     * @return The JSON payload as a string, or null if extraction fails
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getWebhookUrl() {

        return webhookUrl;
    }

    public void setWebhookUrl(String webhookUrl) {

        this.webhookUrl = webhookUrl;

        try {
            new URL(webhookUrl);
        } catch (MalformedURLException e) {
            logger.error("Malformed URL provided: " + webhookUrl, e);
        }
    }

    public String getHeaders() {

        return headers;
    }

    public void setHeaders(String headers) {

        this.headers = headers;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public int getTimeout() {

        return timeout;
    }

    public void setTimeout(int timeout) {

        this.timeout = timeout;
    }
}
