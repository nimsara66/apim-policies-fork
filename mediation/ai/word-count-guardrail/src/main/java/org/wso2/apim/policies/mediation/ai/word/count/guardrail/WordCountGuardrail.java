package org.wso2.apim.policies.mediation.ai.word.count.guardrail;

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
import org.json.JSONObject;

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
public class WordCountGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(WordCountGuardrail.class);

    private int min;
    private int max;
    private String jsonPath = "";
    private boolean doInvert = false;

    /**
     * Initializes the RegexGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("WordCountGuardrail: Initialized.");
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
            logger.debug("Executing WordCountGuardrail mediation");
        }

        try {
            boolean validationResult = validatePayload(messageContext);
            boolean finalResult = doInvert != validationResult;

            if (!finalResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        WordCountGuardrailConstants.WORD_COUNT_GUARDRAIL_ERROR_CODE);
                messageContext.setProperty(WordCountGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(WordCountGuardrailConstants.CUSTOM_HTTP_SC,
                        WordCountGuardrailConstants.WORD_COUNT_GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("Initiating WordCountGuardrail fault sequence");
                }

                Mediator faultMediator = messageContext.getSequence(WordCountGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Error during WordCountGuardrail mediation", e);
        }

        return true;
    }

    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating WordCountGuardrail payload");
        }

        int count = getWordCount(messageContext);
        return isCountWithinBounds(count);
    }

    private boolean isCountWithinBounds(int count) {
        return this.min <= count && this.max >= count;
    }

    private int getWordCount(MessageContext messageContext) {
        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return 0;
        }

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return countWords(jsonContent);
        }

        // Check if any extracted value by json path matches the regex pattern
        return countWords(JsonPath.read(jsonContent, this.jsonPath).toString());
    }

    private int countWords(String text) {

        if (logger.isDebugEnabled()) {
            logger.debug("Counting words from text: " + text);
        }

        if (text == null || text.trim().isEmpty()) {
            return 0;
        }

        // Remove quotes at beginning and end
        String cleanedText = text.replaceAll("^\"|\"$", "").trim();

        // Split using regex that detects word-ending punctuation
        String[] words =
                cleanedText.split("\\s+");

        // Handle empty string case after cleaning
        if (words.length == 1 && words[0].isEmpty()) {
            return 0;
        }
        return words.length;
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
     *
     * @return A JSON object with assessment details
     */
    private String buildAssessmentObject() {
        if (logger.isDebugEnabled()) {
            logger.debug("Regex Guardrail assessment creation");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put("action", "GUARDRAIL_INTERVENED");
        assessmentObject.put("actionReason", "Guardrail blocked.");
        String message = String.format(
                "Violation of word count detected: expected %s %d %s %d words.",
                doInvert ? "less than" : "between", this.min, doInvert ? "or more than" : "and", this.max
        );

        return assessmentObject.toString();
    }

    public int getMin() {

        return min;
    }

    public void setMin(int min) {

        this.min = min;
    }

    public int getMax() {

        return max;
    }

    public void setMax(int max) {

        this.max = max;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public boolean isDoInvert() {

        return doInvert;
    }

    public void setDoInvert(boolean doInvert) {

        this.doInvert = doInvert;
    }
}
