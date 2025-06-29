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

package org.wso2.apim.policies.mediation.ai.azure.content.safety.guardrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
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
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Mediator for Azure Content Safety Prompt Shield, which validates user prompt content
 * against Azure's content safety API. This mediator is designed to detect unsafe content
 * or prompt injection attempts in incoming API requests by analyzing payloads or
 * extracted fields using JSONPath.
 *
 * <h3>Features:</h3>
 * <ul>
 *   <li>Integrates with Azure Content Safety API to detect harmful or adversarial prompts</li>
 *   <li>Allows payload targeting using configurable JSONPath expressions</li>
 *   <li>Provides structured assessment reports for failed validations</li>
 *   <li>Fails or continues on API errors based on configuration</li>
 * </ul>
 *
 * <p>
 * When unsafe content is detected, the mediator triggers a fault sequence and adds
 * error information to the message context, halting further processing.
 * </p>
 */
public class AzureContentSafetyPromptShield extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(AzureContentSafetyPromptShield.class);

    private String name;
    private String contentSafetyEndpoint;
    private String contentSafetyApiKey;
    private int timeout;
    private String jsonPath = "";
    private boolean blockOnError = true;
    private boolean hideAssessment = false;

    /**
     * Initializes the AzureContentSafetyPromptShield mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing AzureContentSafetyPromptShield.");
        }
    }

    /**
     * Destroys the AzureContentSafetyPromptShield mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Beginning payload validation.");
        }

        try {
            boolean validationResult = validatePayload(messageContext);

            if (!validationResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        AzureContentSafetyConstants.GUARDRAIL_APIM_EXCEPTION_CODE);
                messageContext.setProperty(AzureContentSafetyConstants.ERROR_TYPE,
                        AzureContentSafetyConstants.AZURE_CONTENT_SAFETY_PROMPT_GUARD);
                messageContext.setProperty(AzureContentSafetyConstants.CUSTOM_HTTP_SC,
                        AzureContentSafetyConstants.GUARDRAIL_ERROR_CODE);

                // Build assessment details
//                String assessmentObject = buildAssessmentObject(this.name,
//                        this.buildAssessment);
//                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("Validation failed - triggering fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(AzureContentSafetyConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Exception occurred during mediation.", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    AzureContentSafetyConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, "Error occurred during AzureContentSafetyPromptShield mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);
        }

        return true;
    }

    /**
     * Validates the payload of the message against the configured regex pattern.
     * If a JSON path is specified, validation is performed only on the extracted value,
     * otherwise the entire payload is validated.
     *
     * @param messageContext The message context containing the payload to validate
     * @return {@code true} if the payload matches the pattern, {@code false} otherwise
     */
    private boolean validatePayload(MessageContext messageContext) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Extracting content for validation.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return validate(jsonContent, messageContext);
        }

        String content = JsonPath.read(jsonContent, this.jsonPath).toString();

        // Remove quotes at beginning and end
        String cleanedText = content.replaceAll(AzureContentSafetyConstants.TEXT_CLEAN_REGEX, "").trim();

        // Check if any extracted value by json path matches the regex pattern
        return validate(cleanedText, messageContext);
    }

    private boolean validate(String jsonContent, MessageContext messageContext) throws IOException {

        String url = this.contentSafetyEndpoint
                + AzureContentSafetyConstants.AZURE_CONTENT_SAFETY_PROMPT_SHIELD_ENDPOINT;

        // Create JSON body
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonBody = objectMapper.writeValueAsString(Map.of("userPrompt", jsonContent));

        // Configure request timeouts
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(this.timeout)
                .setConnectionRequestTimeout(this.timeout)
                .setSocketTimeout(this.timeout)
                .build();

        for (int attempt = 1; attempt <= 3; attempt++) {
            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setDefaultRequestConfig(requestConfig)
                    .build()) {

                HttpPost httpPost = new HttpPost(url);
                httpPost.setHeader("Content-Type", "application/json");
                httpPost.setHeader("Ocp-Apim-Subscription-Key", this.contentSafetyApiKey);
                httpPost.setEntity(new StringEntity(jsonBody, StandardCharsets.UTF_8));

                int statusCode = -1;
                String responseBody = "";
                try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                    statusCode = response.getStatusLine().getStatusCode();
                    responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                    if (statusCode == 200) {
                        // Extract "attackDetected" from response JSON
                        JsonNode rootNode = objectMapper.readTree(responseBody);
                        boolean attackDetected = rootNode.path("userPromptAnalysis")
                                .path("attackDetected").asBoolean();

                        // Return negated value (true = safe, false = blocked)
                        if (attackDetected) {
                            String assessmentObject = buildAssessmentObject(jsonContent, messageContext.isResponse());
                            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);
                        }
                        return !attackDetected;
                    } else {
                        logger.warn(String.format("Attempt %d: Exception during API call with response: %s",
                                attempt, responseBody));
                    }
                } catch (IOException e) {
                    logger.warn(String.format("Attempt %d: Content Safety API error (%d): %s",
                            attempt, statusCode, responseBody));
                }
            }

            // Exponential backoff
            try {
                long backoff = (long) Math.pow(2, attempt) * 1000L; // 2s, 4s, 8s, etc.
                Thread.sleep(backoff);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted during backoff", ie);
            }
        }

        // Should not reach here
        if (isBlockOnError()) {
            logger.error("Failed to validate content after maximum retry attempts.");
            throw new IOException("Failed to get embedding after " +
                    3 + " attempts");
        } else {
            logger.warn("Failed to validate content after maximum retry attempts, but continuing processing.");
        }

        return true;
    }

    /**
     * Builds a JSON object containing assessment details for guardrail responses.
     * This JSON includes information about why the guardrail intervened.
     *
     * @return A JSON string representing the assessment object
     */
    public String buildAssessmentObject(String content, boolean isResponse) {

        if (logger.isDebugEnabled()) {
            logger.debug("Building assessment");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(AzureContentSafetyConstants.INTERVENING_GUARDRAIL, this.name);
        assessmentObject.put(AzureContentSafetyConstants.DIRECTION, isResponse? "RESPONSE" : "REQUEST");
        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_REASON,
                "Violation of azure content safety content moderation detected.");

        if (!this.hideAssessment) {
            assessmentObject.put(
                    AzureContentSafetyConstants.ASSESSMENTS,
                    String.format("The extracted content \"%s\" was flagged as unsafe or adversarial by " +
                            "Azure AI Content Safety.", content)
            );
        }
        return assessmentObject.toString();
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

    public String getContentSafetyEndpoint() {

        return contentSafetyEndpoint;
    }

    public void setContentSafetyEndpoint(String contentSafetyEndpoint) {

        this.contentSafetyEndpoint = contentSafetyEndpoint;
    }

    public String getContentSafetyApiKey() {

        return contentSafetyApiKey;
    }

    public void setContentSafetyApiKey(String contentSafetyApiKey) {

        this.contentSafetyApiKey = contentSafetyApiKey;
    }

    public int getTimeout() {

        return timeout;
    }

    public void setTimeout(int timeout) {

        this.timeout = timeout;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public boolean isBlockOnError() {

        return blockOnError;
    }

    public void setBlockOnError(boolean blockOnError) {

        this.blockOnError = blockOnError;
    }

    public boolean isHideAssessment() {

        return hideAssessment;
    }

    public void setHideAssessment(boolean hideAssessment) {

        this.hideAssessment = hideAssessment;
    }
}
