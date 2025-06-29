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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.GuardrailProviderService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Azure Content Safety Content Moderation Guardrail mediator.
 * <p>
 * This mediator integrates with Azure Content Safety APIs to assess message payloads for potentially
 * harmful content such as hate speech, sexual content, self-harm, and violence. It supports configurable
 * severity thresholds for each category and validates the payload based on those thresholds.
 * <p>
 * The content to be validated can be extracted using an optional JSONPath expression. If no JSONPath
 * is configured, the entire payload will be inspected. If the validation fails, the mediator triggers a
 * fault sequence and enriches the message context with assessment details for further inspection.
 * <p>
 * This mediator supports retry logic with exponential backoff when invoking the Azure Content Safety
 * API and allows configurable behavior for whether to fail on errors. It can also generate structured
 * assessment reports based on API responses for auditing or policy enforcement purposes.
 * <p>
 * Expected usage involves deploying this mediator in API request/response flows to enforce
 * content safety policies and comply with moderation standards.
 *
 * <h3>Features:</h3>
 * <ul>
 *   <li>Supports individual threshold configuration for each moderation category</li>
 *   <li>Allows payload targeting using JSONPath</li>
 *   <li>Provides structured assessment reports for failed validations</li>
 *   <li>Includes retry mechanism with exponential backoff for API robustness</li>
 *   <li>Fails or continues on API errors based on configuration</li>
 * </ul>
 *
 * <p>
 * This guardrail is useful in API security and compliance contexts where payloads must be moderated
 * to prevent harmful or unsafe content from being processed or returned.
 */
public class AzureContentSafetyContentModeration extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(AzureContentSafetyContentModeration.class);

    private String name;
    private int hateCategory = -1;
    private int sexualCategory = -1;
    private int selfHarmCategory = -1;
    private int violenceCategory = -1;
    private String jsonPath = "";
    private boolean passthroughOnError = false;
    private boolean showAssessment = false;

    private GuardrailProviderService guardrailProviderService;

    /**
     * Initializes the AzureContentSafetyContentModeration mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing AzureContentSafetyContentModeration.");
        }

        guardrailProviderService =
                org.wso2.apim.policies.mediation.ai.azure.content.safety.guardrail.internal.ServiceReferenceHolder
                        .getInstance()
                        .getGuardrailProviderService();

        if (guardrailProviderService == null) {
            throw new IllegalStateException("Azure Content Safety provider is not registered or available.");
        }
        try {
            guardrailProviderService.init(); // Initialize the provider with required HTTP client and configuration properties.
        } catch (APIManagementException e) {
            throw new IllegalStateException("Failed to initialize Azure Content Safety provider.", e);
        }
    }

    /**
     * Destroys the AzureContentSafetyContentModeration mediator instance and releases any allocated resources.
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
                        AzureContentSafetyConstants.AZURE_CONTENT_SAFETY_CONTENT_MODERATION);
                messageContext.setProperty(AzureContentSafetyConstants.CUSTOM_HTTP_SC,
                        AzureContentSafetyConstants.GUARDRAIL_ERROR_CODE);

                if (logger.isDebugEnabled()) {
                    logger.debug("Validation failed - triggering fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(AzureContentSafetyConstants.FAULT_SEQUENCE_KEY);
                if (faultMediator == null) {
                    messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, "Violation of " + name + " detected.");
                    faultMediator = messageContext.getFaultSequence(); // Fall back to default error sequence
                }
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Exception occurred during mediation.", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    AzureContentSafetyConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Error occurred during AzureContentSafetyContentModeration mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);
            return false; // Stop further processing
        }

        return true;
    }

    /**
     * Validates the payload of the message calling out to Azure Content Safety Content Moderation endpoint.
     * If a JSON path is specified, validation is performed only on the extracted value,
     * otherwise the entire payload is validated.
     *
     * @param messageContext The message context containing the payload to validate
     * @return {@code true} if the payload matches the pattern, {@code false} otherwise
     */
    private boolean validatePayload(MessageContext messageContext) throws APIManagementException {
        if (logger.isDebugEnabled()) {
            logger.debug("Extracting content for validation.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        // If no JSON path is specified, apply validation to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return validate(jsonContent, messageContext);
        }

        String content = JsonPath.read(jsonContent, this.jsonPath).toString();

        // Remove quotes at beginning and end
        String cleanedText = content.replaceAll(AzureContentSafetyConstants.TEXT_CLEAN_REGEX, "").trim();

        // Check if any extracted value by json path matches the regex pattern
        return validate(cleanedText, messageContext);
    }

    private boolean validate(String jsonContent, MessageContext messageContext) throws APIManagementException {
        // Prepare callout configuration
        Map<String, Object> callOutConfig = new HashMap<>();
        callOutConfig.put("service", AzureContentSafetyConstants.AZURE_CONTENT_SAFETY_CONTENT_MODERATION_ENDPOINT);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> requestPayload = new HashMap<>();
        requestPayload.put("text", jsonContent);
        Map<String, Integer> categoryMap = Map.of(
                "Hate", hateCategory,
                "Sexual", sexualCategory,
                "SelfHarm", selfHarmCategory,
                "Violence", violenceCategory
        );
        List<String> categories = categoryMap.entrySet().stream()
                .filter(e -> e.getValue() >= 0 && e.getValue() <= 7)
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());

        if (categories.isEmpty()) {
            throw new APIManagementException("Invalid moderation severity levels configured. " +
                    "Ensure severity levels are set to values between 0 and 7.");
        }
        requestPayload.put("categories", categories);
        requestPayload.put("haltOnBlocklistHit", true);
        requestPayload.put("outputType", "EightSeverityLevels");

        callOutConfig.put("request_payload", requestPayload);
        try {
            String responseBody = guardrailProviderService.callOut(callOutConfig);
            JsonNode rootNode = objectMapper.readTree(responseBody);
            JsonNode categoriesAnalysis = rootNode.path("categoriesAnalysis");

            for (JsonNode categoryNode : categoriesAnalysis) {
                String category = categoryNode.path("category").asText();
                int severity = categoryNode.path("severity").asInt();

                Integer threshold = categoryMap.get(category);
                if (severity >= threshold) {
                    // Build assessment details
                    String assessmentObject = buildAssessmentObject(
                            jsonContent, categoryMap, categoriesAnalysis, messageContext.isResponse());
                    messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                    return false; // Unsafe
                }

            }
            return true; // Safe
        } catch (APIManagementException | JsonProcessingException e) {
            if (!passthroughOnError) {
                logger.error("API call to Azure Content Safety has failed or returned an unexpected response.");
                String assessmentObject = buildAssessmentObject(messageContext.isResponse());
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);
                return false; // Guardrail intervention after maximum retries reached
            } else {
                logger.warn("API call to Azure Content Safety has failed or returned an unexpected response, " +
                        "but continuing processing.");
            }
        }

        return true;
    }

    /**
     * Builds a JSON object containing assessment details for guardrail responses.
     * This JSON includes information about why the guardrail intervened.
     *
     * @return A JSON string representing the assessment object
     */
    public String buildAssessmentObject(String content, Map<String, Integer> severities,
                                        JsonNode categoriesAnalysis, boolean isResponse) {

        if (logger.isDebugEnabled()) {
            logger.debug("Building guardrail assessment object.");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(AzureContentSafetyConstants.INTERVENING_GUARDRAIL, this.name);
        assessmentObject.put(AzureContentSafetyConstants.DIRECTION, isResponse? "RESPONSE" : "REQUEST");
        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_REASON,
                "Violation of azure content safety content moderation detected.");

        if (showAssessment && categoriesAnalysis != null
                && categoriesAnalysis.isArray() && severities != null && !severities.isEmpty()) {
            JSONObject assessmentsWrapper = new JSONObject();
            assessmentsWrapper.put("inspectedContent", content); // Include the original content

            JSONArray assessmentsArray = new JSONArray();

            for (JsonNode categoryNode : categoriesAnalysis) {
                String category = categoryNode.path("category").asText();
                int severity = categoryNode.path("severity").asInt();
                Integer threshold = severities.getOrDefault(category, -1);

                JSONObject categoryAssessment = new JSONObject();
                categoryAssessment.put("category", category);
                categoryAssessment.put("severity", severity);
                categoryAssessment.put("threshold", threshold);
                categoryAssessment.put("result", (threshold >= 0 && severity >= threshold) ? "FAIL" : "PASS");

                assessmentsArray.put(categoryAssessment);
            }

            assessmentsWrapper.put("categories", assessmentsArray);
            assessmentObject.put(AzureContentSafetyConstants.ASSESSMENTS, assessmentsWrapper);
        } else if (showAssessment) {
            assessmentObject.put(AzureContentSafetyConstants.ASSESSMENTS, categoriesAnalysis);
        }
        return assessmentObject.toString();
    }

    /**
     * Builds a JSON object containing assessment details for guardrail responses.
     * This JSON includes information about why the guardrail intervened.
     *
     * @return A JSON string representing the assessment object
     */
    public String buildAssessmentObject(boolean isResponse) {

        if (logger.isDebugEnabled()) {
            logger.debug("Building guardrail assessment object.");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(AzureContentSafetyConstants.INTERVENING_GUARDRAIL, this.name);
        assessmentObject.put(AzureContentSafetyConstants.DIRECTION, isResponse? "RESPONSE" : "REQUEST");
        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_REASON,
                "Violation of azure content safety content moderation detected.");

        if (showAssessment) {
            assessmentObject.put(AzureContentSafetyConstants.ASSESSMENTS,
                    "Azure Content Safety API is unreachable or returned an invalid response.");
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
    private String extractJsonContent(MessageContext messageContext) {
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

    public int getHateCategory() {

        return hateCategory;
    }

    public void setHateCategory(int hateCategory) {

        this.hateCategory = hateCategory;
    }

    public int getSexualCategory() {

        return sexualCategory;
    }

    public void setSexualCategory(int sexualCategory) {

        this.sexualCategory = sexualCategory;
    }

    public int getSelfHarmCategory() {

        return selfHarmCategory;
    }

    public void setSelfHarmCategory(int selfHarmCategory) {

        this.selfHarmCategory = selfHarmCategory;
    }

    public int getViolenceCategory() {

        return violenceCategory;
    }

    public void setViolenceCategory(int violenceCategory) {

        this.violenceCategory = violenceCategory;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public boolean isPassthroughOnError() {

        return passthroughOnError;
    }

    public void setPassthroughOnError(boolean passthroughOnError) {

        this.passthroughOnError = passthroughOnError;
    }

    public boolean isShowAssessment() {

        return showAssessment;
    }

    public void setShowAssessment(boolean showAssessment) {

        this.showAssessment = showAssessment;
    }
}
