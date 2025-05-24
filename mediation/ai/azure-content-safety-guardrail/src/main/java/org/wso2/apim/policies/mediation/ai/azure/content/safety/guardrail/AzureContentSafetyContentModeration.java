package org.wso2.apim.policies.mediation.ai.azure.content.safety.guardrail;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class AzureContentSafetyContentModeration extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(AzureContentSafetyContentModeration.class);

    private String name;
    private String contentSafetyEndpoint;
    private String contentSafetyApiKey;
    private int timeout;
    private String jsonPath = "";
    private boolean failOnError = true;
    private boolean buildAssessment = true;

    /**
     * Initializes the RegexGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("RegexGuardrail: Initialized.");
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
            logger.debug("AzureContentSafetyContentModeration: Beginning payload validation.");
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
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("AzureContentSafetyContentModeration: Validation failed - triggering fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(AzureContentSafetyConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("AzureContentSafetyContentModeration: Exception occurred during mediation.", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    AzureContentSafetyConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Error occurred during AzureContentSafetyContentModeration mediation");
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
    private boolean validatePayload(MessageContext messageContext) throws JsonProcessingException {
        if (logger.isDebugEnabled()) {
            logger.debug("AzureContentSafetyContentModeration: Extracting content for validation.");
        }

        String jsonContent = AzureContentSafetyUtils.extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return validate(jsonContent);
        }

        String content = JsonPath.read(jsonContent, this.jsonPath).toString();

        // Remove quotes at beginning and end
        String cleanedText = content.replaceAll(AzureContentSafetyConstants.JSON_CLEAN_REGEX, "").trim();

        // Check if any extracted value by json path matches the regex pattern
        return validate(cleanedText);
    }

    private boolean validate(String jsonContent) throws JsonProcessingException {
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
        HttpRequestRetryHandler retryHandler =
                new DefaultHttpRequestRetryHandler(AzureContentSafetyConstants.AZURE_CONTENT_SAFETY_RETRY_COUNT,
                        false);

        try (CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .setRetryHandler(retryHandler)
                .build()) {

            HttpPost httpPost = new HttpPost(url);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("Ocp-Apim-Subscription-Key", this.contentSafetyApiKey);
            httpPost.setEntity(new StringEntity(jsonBody, StandardCharsets.UTF_8));

            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                int statusCode = response.getStatusLine().getStatusCode();
                String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                if (statusCode == 200) {
                    // Extract "attackDetected" from response JSON
                    JsonNode rootNode = objectMapper.readTree(responseBody);
                    boolean attackDetected = rootNode.path("userPromptAnalysis")
                            .path("attackDetected").asBoolean();

                    // Return negated value (true = safe, false = blocked)
                    return !attackDetected;
                } else {
                    logger.warn("Content Safety API returned status: " + statusCode + ", body: " + responseBody);
                    return !isFailOnError();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Builds a JSON object containing assessment details for guardrail responses.
     * This JSON includes information about why the guardrail intervened.
     *
     * @return A JSON string representing the assessment object
     */
    public String buildAssessmentObject() {
        if (logger.isDebugEnabled()) {
            logger.debug("RegexGuardrail: Building assessment");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(AzureContentSafetyConstants.INTERVENING_GUARDRAIL, this.name);
        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_REASON, "Violation of regular expression detected.");

        if (this.buildAssessment) {
            assessmentObject.put(AzureContentSafetyConstants.ASSESSMENTS,
                    "Violated regular expression: ");
        }
        return assessmentObject.toString();
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

    public boolean isFailOnError() {

        return failOnError;
    }

    public void setFailOnError(boolean failOnError) {

        this.failOnError = failOnError;
    }

    public boolean isBuildAssessment() {

        return buildAssessment;
    }

    public void setBuildAssessment(boolean buildAssessment) {

        this.buildAssessment = buildAssessment;
    }
}
