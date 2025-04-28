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
 * Word Count Guardrail mediator.
 * <p>
 * A mediator that enforces minimum and maximum word count constraints on API payloads.
 * It can operate in both blocking mode (where non-compliant payloads are rejected)
 * and inverted mode (where payloads must fall outside the specified range).
 * <p>
 * Supports evaluating the entire JSON payload or specific sections using JsonPath expressions.
 * Upon violation, detailed error information is populated into the message context,
 * and an optional fault sequence can be invoked to handle the error gracefully.
 */
public class WordCountGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(WordCountGuardrail.class);

    private int min;
    private int max;
    private String jsonPath = "";
    private boolean doInvert = false;

    /**
     * Initializes the WordCountGuardrail mediator.
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
     * Destroys the WordCountGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    /**
     * Executes the WordCountGuardrail mediation logic.
     * <p>
     * Validates the payload's word count against the configured constraints.
     * If validation fails, populates error details into the message context and optionally
     * invokes a configured fault sequence to handle the violation.
     *
     * @param messageContext The message context containing the payload to validate.
     * @return {@code true} if mediation should continue, {@code false} if processing should halt.
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("WordCountGuardrail: Beginning guardrail evaluation.");
        }

        try {
            boolean validationResult = validatePayload(messageContext);
            boolean finalResult = doInvert != validationResult;

            if (!finalResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        WordCountGuardrailConstants.ERROR_CODE);
                messageContext.setProperty(WordCountGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(WordCountGuardrailConstants.CUSTOM_HTTP_SC,
                        WordCountGuardrailConstants.ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("WordCountGuardrail: Triggering fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(WordCountGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("WordCountGuardrail: Error during guardrail mediation.", e);
        }

        return true;
    }

    /**
     * Validates whether the word count of the extracted payload falls within the configured bounds.
     *
     * @param messageContext The message context containing the payload.
     * @return {@code true} if the payload satisfies the word count constraints; {@code false} otherwise.
     */
    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("WordCountGuardrail: Validating payload word count.");
        }

        int count = getWordCount(messageContext);
        return isCountWithinBounds(count);
    }

    /**
     * Checks whether the given word count is within the configured minimum and maximum bounds.
     *
     * @param count The number of words to evaluate.
     * @return {@code true} if the word count is within bounds; {@code false} otherwise.
     */
    private boolean isCountWithinBounds(int count) {
        return this.min <= count && this.max >= count;
    }

    /**
     * Extracts and counts the number of words in the payload, optionally using a JsonPath expression.
     *
     * @param messageContext The message context containing the payload.
     * @return The number of words detected.
     */
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

    /**
     * Counts the number of words in a given text.
     * <p>
     * Words are separated by whitespace. Quotes at the beginning and end of the text are removed
     * before counting.
     *
     * @param text The text to analyze.
     * @return The number of words found.
     */
    private int countWords(String text) {

        if (logger.isDebugEnabled()) {
            logger.debug("WordCountGuardrail: Counting words in extracted text.");
        }

        if (text == null || text.trim().isEmpty()) {
            return 0;
        }

        // Remove quotes at beginning and end
        String cleanedText = text.replaceAll(WordCountGuardrailConstants.TEXT_CLEAN_REGEX, "").trim();

        // Split using regex that detects word-ending punctuation
        String[] words =
                cleanedText.split(WordCountGuardrailConstants.WORD_SPLIT_REGEX);

        // Handle empty string case after cleaning
        if (words.length == 1 && words[0].isEmpty()) {
            return 0;
        }
        return words.length;
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
     * Builds a JSON object containing assessment details for guardrail responses.
     * This JSON includes information about why the guardrail intervened.
     *
     * @return A JSON string representing the assessment object
     */
    private String buildAssessmentObject() {
        if (logger.isDebugEnabled()) {
            logger.debug("Regex Guardrail assessment creation");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(WordCountGuardrailConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(WordCountGuardrailConstants.ASSESSMENT_REASON, "Guardrail blocked.");
        String message = String.format(
                "Violation of word count detected: expected %s %d %s %d words.",
                doInvert ? "less than" : "between", this.min, doInvert ? "or more than" : "and", this.max
        );
        assessmentObject.put(WordCountGuardrailConstants.ASSESSMENTS, message);

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
