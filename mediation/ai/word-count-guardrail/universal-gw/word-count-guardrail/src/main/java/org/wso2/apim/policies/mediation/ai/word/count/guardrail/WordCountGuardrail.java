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

import java.util.Arrays;

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

    private String name;
    private int min;
    private int max;
    private String jsonPath = "";
    private boolean invert = false;
    private boolean showAssessment = false;

    /**
     * Initializes the WordCountGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing WordCountGuardrail.");
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
            logger.debug("Beginning guardrail evaluation.");
        }

        try {
            int count = getWordCount(messageContext);
            boolean validationResult = isCountWithinBounds(count);
            boolean finalResult = invert != validationResult;

            if (!finalResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        WordCountGuardrailConstants.GUARDRAIL_APIM_EXCEPTION_CODE);
                messageContext.setProperty(WordCountGuardrailConstants.ERROR_TYPE,
                        WordCountGuardrailConstants.WORD_COUNT_GUARDRAIL);
                messageContext.setProperty(WordCountGuardrailConstants.CUSTOM_HTTP_SC,
                        WordCountGuardrailConstants.GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject(count, messageContext.isResponse());
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("Triggering fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(WordCountGuardrailConstants.FAULT_SEQUENCE_KEY);
                if (faultMediator == null) {
                    messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                            "Violation of " + name + " detected.");
                    faultMediator = messageContext.getFaultSequence(); // Fall back to default error sequence
                }

                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Error during guardrail mediation.", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    WordCountGuardrailConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Error occurred during WordCountGuardrail mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);
            return false; // Stop further processing
        }

        return true;
    }

    /**
     * Checks whether the given word count is within the configured minimum and maximum bounds.
     *
     * @param count The number of words to evaluate.
     * @return {@code true} if the word count is within bounds; {@code false} otherwise.
     */
    private boolean isCountWithinBounds(int count) {
        return min <= count && max >= count;
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
        if (jsonPath == null || jsonPath.trim().isEmpty()) {
            return countWords(jsonContent);
        }

        // Check if any extracted value by json path matches the regex pattern
        return countWords(JsonPath.read(jsonContent, jsonPath).toString());
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
            logger.debug("Counting words in extracted text.");
        }

        return (int) Arrays.stream(
                        text == null ? new String[0] :
                                text.replaceAll(WordCountGuardrailConstants.TEXT_CLEAN_REGEX, "")
                                        .trim()
                                        .split(WordCountGuardrailConstants.WORD_SPLIT_REGEX))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .count();
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
    private String buildAssessmentObject(int count, boolean isResponse) {
        if (logger.isDebugEnabled()) {
            logger.debug("Building guardrail assessment object.");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(WordCountGuardrailConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(WordCountGuardrailConstants.INTERVENING_GUARDRAIL, name);
        assessmentObject.put(WordCountGuardrailConstants.DIRECTION, isResponse? "RESPONSE" : "REQUEST");
        assessmentObject.put(WordCountGuardrailConstants.ASSESSMENT_REASON,
                "Violation of applied word count constraints detected.");

        if (showAssessment) {
            String message = String.format(
                    "Violation of word count detected. Expected %s %d %s %d words. But found %d words.",
                    invert ? "less than" : "between", min, invert ? "or more than" : "and", max, count
            );
            assessmentObject.put(WordCountGuardrailConstants.ASSESSMENTS, message);
        }
        return assessmentObject.toString();
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
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

    public boolean isInvert() {

        return invert;
    }

    public void setInvert(boolean invert) {

        this.invert = invert;
    }

    public boolean isShowAssessment() {

        return showAssessment;
    }

    public void setShowAssessment(boolean showAssessment) {

        this.showAssessment = showAssessment;
    }
}
