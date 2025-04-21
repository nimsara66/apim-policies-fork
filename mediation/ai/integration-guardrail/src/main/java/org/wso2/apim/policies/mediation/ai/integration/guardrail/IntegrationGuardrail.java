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
 * Regex Guardrail mediator for WSO2 API Gateway.
 *
 * This mediator provides content filtering capabilities for API payloads using regular expression patterns.
 * It intercepts API requests or responses, validates the JSON content against configured regex patterns,
 * and can block requests that match (or optionally don't match) the specified patterns.
 *
 * Key features:
 * - Flexible pattern matching - Apply regex patterns to entire JSON payloads or specific fields
 * - JsonPath support - Target validation to specific parts of JSON payloads using JsonPath expressions
 * - Invertible logic - Block content that matches OR doesn't match patterns
 * - Custom error responses - Return detailed assessment information when content is blocked
 *
 * When content violates the guardrail settings, the mediator triggers a fault sequence with
 * appropriate error details and blocks further processing of the request/ response.
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
     * Destroys the RegexGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Executing JSONSchemaGuardrail mediation");
        }

        try {
            if (!validatePayload(messageContext)) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        IntegrationGuardrailConstants.JSON_SCHEMA_GUARDRAIL_ERROR_CODE);
                messageContext.setProperty(IntegrationGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(IntegrationGuardrailConstants.CUSTOM_HTTP_SC,
                        IntegrationGuardrailConstants.JSON_SCHEMA_GUARDRAIL_ERROR_CODE);

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

    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating JSONSchemaGuardrail payload");
        }

        Map<String, Object> guardrailMetadata = new HashMap<>();

        if (!messageContext.isResponse()) {
            // Request flow
            guardrailMetadata.put("requestPayload", extractJsonContent(messageContext));
        } else {
            // Response flow
            guardrailMetadata.put("responsePayload", extractJsonContent(messageContext));
        }

        if (this.url != null) {
            try {
                String response = sendPostRequestToWebhook(guardrailMetadata);
                JsonObject jsonResponse = JsonParser.parseString(response).getAsJsonObject();

                // Build assessment details
                buildAssessmentObject(jsonResponse);
                return jsonResponse.has("verdict") && jsonResponse.get("verdict").getAsBoolean();
            } catch (Exception e) {
                log.error("Error sending webhook POST request.", e);
                // If a verdict cannot be extracted, assume the request/ response is valid
                return true;
            }
        }

        return true;
    }

    /**
     * Sends a POST request to a webhook with the provided metadata.
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
            httpPost.setHeader("Content-Type", "application/json");

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
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    /**
     * Builds a JSON object containing assessment details from the guardrail response.
     */
    private void buildAssessmentObject(JsonObject response) {
        if (logger.isDebugEnabled()) {
            logger.debug("Integration Guardrail assessment creation");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put("action", response.has("action")
                ? response.get("action"): "GUARDRAIL_INTERVENED");
        assessmentObject.put("actionReason", response.has("actionReason")
                ? response.get("actionReason"): "Guardrail blocked.");
        assessmentObject.put("assessments", response.has("assessments")
                ? response.get("assessments"): "Violation of integration guardrail detected.");

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
