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
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
    private String contentSafetyEndpoint;
    private String contentSafetyApiKey;
    private int timeout = 3000; // Default timeout in milliseconds (3 seconds);
    private String jsonPath = "";
    private boolean blockOnError = true;
    private boolean hideAssessment = false;

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
    private boolean validatePayload(MessageContext messageContext) throws IOException {
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

    private boolean validate(String jsonContent, MessageContext messageContext) throws IOException {
        String url = this.contentSafetyEndpoint
                + AzureContentSafetyConstants.AZURE_CONTENT_SAFETY_CONTENT_MODERATION_ENDPOINT;

        // Prepare request payload
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
            throw new RuntimeException("Invalid moderation severity levels configured. " +
                    "Ensure severity levels are set to values between 0 and 7.");
        }
        requestPayload.put("categories", categories);

        requestPayload.put("haltOnBlocklistHit", true);
        requestPayload.put("outputType", "EightSeverityLevels");

        String jsonBody = objectMapper.writeValueAsString(requestPayload);

        // Set timeouts
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(this.timeout)
                .setConnectionRequestTimeout(this.timeout)
                .setSocketTimeout(this.timeout)
                .build();

        int statusCode = -1;
        String responseBody = "";

        for (int attempt = 1; attempt <= AzureContentSafetyConstants.AZURE_CONTENT_SAFETY_MAX_RETRY_COUNT; attempt++) {
            try (CloseableHttpClient httpClient = HttpClients.custom()
                    .setDefaultRequestConfig(requestConfig)
                    .build()) {

                HttpPost httpPost = new HttpPost(url);
                httpPost.setHeader("Content-Type", "application/json");
                httpPost.setHeader("Ocp-Apim-Subscription-Key", this.contentSafetyApiKey);
                httpPost.setEntity(new StringEntity(jsonBody, StandardCharsets.UTF_8));

                try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                    statusCode = response.getStatusLine().getStatusCode();
                    responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                    if (statusCode == 200) {
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
                    } else {
                        logger.warn(String.format("Attempt %d: Exception during API call with response: %s",
                                attempt, responseBody));
                    }
                }
            } catch (IOException e) {
                logger.warn(String.format("Attempt %d: Content Safety API error (%d): %s",
                        attempt, statusCode, responseBody));
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
            logger.error("Failed to get embedding after " +
                    AzureContentSafetyConstants.AZURE_CONTENT_SAFETY_MAX_RETRY_COUNT + " attempts");

            String assessmentObject = buildAssessmentObject(statusCode, responseBody, messageContext.isResponse());
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);
            return false; // Guardrail intervention after maximum retries reached
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

        if (!this.hideAssessment && categoriesAnalysis != null
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
        } else if (!this.hideAssessment) {
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
    public String buildAssessmentObject(int statusCode, String responseBody, boolean isResponse) {

        if (logger.isDebugEnabled()) {
            logger.debug("Building guardrail assessment object.");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(AzureContentSafetyConstants.INTERVENING_GUARDRAIL, this.name);
        assessmentObject.put(AzureContentSafetyConstants.DIRECTION, isResponse? "RESPONSE" : "REQUEST");
        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_REASON,
                "Azure Content Safety Content Moderation resource unreachable or invalid response received.");

        if (!this.hideAssessment) {
            assessmentObject.put(AzureContentSafetyConstants.ASSESSMENTS,
                    "Azure Content Safety API returned status code: " + statusCode +
                            ", response body: " + responseBody);
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
