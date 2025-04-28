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
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
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

import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

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

    private String webhookUrl;
    private String headers;
    private String jsonPath = "";
    private int timeout = 60000;
    private URL url;
    private String assessment;

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
            logger.debug("Executing JSONSchemaGuardrail mediation");
        }

        try {
            if (!validatePayload(messageContext)) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        IntegrationGuardrailConstants.ERROR_CODE);
                messageContext.setProperty(IntegrationGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(IntegrationGuardrailConstants.CUSTOM_HTTP_SC,
                        IntegrationGuardrailConstants.ERROR_CODE);

                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, this.assessment);

                if (logger.isDebugEnabled()) {
                    logger.debug("Initiating Integration Guardrail fault sequence");
                }

                Mediator faultMediator = messageContext.getSequence(IntegrationGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Error during JSONSchemaGuardrail mediation", e);
        }

        return true;
    }

    /**
     * Validates the payload by posting it to the configured webhook and interpreting the response.
     *
     * @param messageContext The message context containing the payload.
     * @return {@code true} if the payload passes validation; {@code false} if a violation is detected.
     */
    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating JSONSchemaGuardrail payload");
        }

        Map<String, Object> guardrailMetadata = new HashMap<>();

        if (!messageContext.isResponse()) {
            // Request flow
            guardrailMetadata.put(IntegrationGuardrailConstants.REQUEST_PAYLOAD_KEY,
                    extractJsonContent(messageContext));
        } else {
            // Response flow
            guardrailMetadata.put(IntegrationGuardrailConstants.RESPONSE_PAYLOAD_KEY,
                    extractJsonContent(messageContext));
        }

        if (this.url != null) {
            try {
                String response = sendPostRequestToWebhook(guardrailMetadata);
                JsonObject jsonResponse = JsonParser.parseString(response).getAsJsonObject();

                // Build assessment details
                buildAssessmentObject(jsonResponse);
                return jsonResponse.has(IntegrationGuardrailConstants.VERDICT)
                        && jsonResponse.get(IntegrationGuardrailConstants.VERDICT).getAsBoolean();
            } catch (Exception e) {
                log.error("Error sending webhook POST request.", e);
                // If a verdict cannot be extracted, assume the request/ response is valid
                return true;
            }
        }

        return true;
    }

    /**
     * Sends a POST request to the configured webhook URL with the provided metadata.
     * <p>
     * Custom headers can also be included if specified.
     *
     * @param metadata A map containing payload metadata to be sent.
     * @return The webhook's response body as a string.
     * @throws Exception If an error occurs while sending the request or receiving the response.
     */
    private String sendPostRequestToWebhook(Map<String, Object> metadata) throws Exception {

        // Create request config with specified timeouts
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(this.timeout)
                .setSocketTimeout(this.timeout)
                .setConnectionRequestTimeout(this.timeout)
                .build();

        try (CloseableHttpClient httpClient = HttpClients.custom().setDefaultRequestConfig(requestConfig).build()) {
            HttpPost httpPost = new HttpPost(webhookUrl);

            // Set default Content-Type header
            httpPost.setHeader(IntegrationGuardrailConstants.CONTENT_TYPE_HEADER, "application/json");

            // Apply custom headers if provided
            if (this.headers != null && !this.headers.isEmpty()) {
                Map<String, String> customHeaders = new Gson().fromJson(
                        this.headers,
                        new TypeToken<Map<String, String>>() {
                        }.getType());

                for (Map.Entry<String, String> header : customHeaders.entrySet()) {
                    if (header.getKey() != null && header.getValue() != null) {
                        httpPost.setHeader(header.getKey(), header.getValue());
                    }
                }
            }

            // Set request body
            String payload = new Gson().toJson(metadata);
            StringEntity entity = new StringEntity(payload, StandardCharsets.UTF_8);
            httpPost.setEntity(entity);

            if (logger.isDebugEnabled()) {
                logger.debug("Sending request to webhook");
            }

            // Execute the request
            HttpResponse response = httpClient.execute(httpPost);

            // Process response
            HttpEntity responseEntity = response.getEntity();
            String responseBody = EntityUtils.toString(responseEntity);

            // Check response status
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpURLConnection.HTTP_OK) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Received successful response from webhook");
                }
                return responseBody;
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Webhook request failed with status code: " + statusCode);
                logger.debug("Response: " + responseBody);
            }
            return "";
        }
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

    /**
     * Builds an assessment object containing details from the webhook response.
     * <p>
     * Populates fields such as action, actionReason, and assessments based on the webhook response,
     * or defaults if fields are not present.
     *
     * @param response The JSON object received from the webhook.
     */
    private void buildAssessmentObject(JsonObject response) {
        if (logger.isDebugEnabled()) {
            logger.debug("Integration Guardrail assessment creation");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(IntegrationGuardrailConstants.ASSESSMENT_ACTION,
                response.has(IntegrationGuardrailConstants.ASSESSMENT_ACTION)
                ? response.get(IntegrationGuardrailConstants.ASSESSMENT_ACTION): "GUARDRAIL_INTERVENED");
        assessmentObject.put(IntegrationGuardrailConstants.ASSESSMENT_REASON,
                response.has(IntegrationGuardrailConstants.ASSESSMENT_REASON)
                ? response.get(IntegrationGuardrailConstants.ASSESSMENT_REASON): "Guardrail blocked.");
        assessmentObject.put(IntegrationGuardrailConstants.ASSESSMENTS,
                response.has(IntegrationGuardrailConstants.ASSESSMENTS)
                ? response.get(IntegrationGuardrailConstants.ASSESSMENTS):
                        "Violation of integration guardrail detected.");

        this.assessment = assessmentObject.toString();
    }

    public String getWebhookUrl() {

        return webhookUrl;
    }

    public void setWebhookUrl(String webhookUrl) {

        this.webhookUrl = webhookUrl;

        try {
            this.url = new URL(webhookUrl);
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
