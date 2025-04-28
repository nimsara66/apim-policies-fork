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

package org.wso2.apim.policies.mediation.ai.sentence.count.guardrail;

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
 * Sentence Count Guardrail mediator.
 * <p>
 * A Synapse mediator that enforces content moderation by validating the number of sentences
 * in a JSON payload against configured minimum and maximum bounds.
 * <p>
 * Supports selective validation through JsonPath expressions and optional inversion logic
 * to define when mediation should block processing. If a violation occurs, a fault sequence
 * is triggered with detailed assessment metadata attached.
 */
public class SentenceCountGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(SentenceCountGuardrail.class);

    private int min;
    private int max;
    private String jsonPath = "";
    private boolean doInvert = false;

    /**
     * Initializes the SentenceCountGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("SentenceCountGuardrail: Initialized.");
        }
    }

    /**
     * Destroys the SentenceCountGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    /**
     * Mediates an incoming message by validating its sentence count.
     * <p>
     * If the count violates configured bounds (considering inversion logic),
     * the mediator triggers a fault sequence and halts further processing.
     *
     * @param messageContext the current message context.
     * @return true if processing should continue, false if blocked due to sentence count violation.
     */

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("SentenceCountGuardrail: Beginning guardrail evaluation.");
        }

        try {
            boolean validationResult = validatePayload(messageContext);
            boolean finalResult = doInvert != validationResult;

            if (!finalResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        SentenceCountGuardrailConstants.ERROR_CODE);
                messageContext.setProperty(SentenceCountGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(SentenceCountGuardrailConstants.CUSTOM_HTTP_SC,
                        SentenceCountGuardrailConstants.ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("SentenceCountGuardrail: Triggering fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(SentenceCountGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("SentenceCountGuardrail: Error during guardrail mediation.", e);
        }

        return true;
    }

    /**
     * Validates the payload by counting sentences and checking if it falls within the allowed range.
     *
     * @param messageContext the current message context.
     * @return true if the sentence count is within bounds, false otherwise.
     */
    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("SentenceCountGuardrail: Validating payload sentence count.");
        }

        int count = getSentenceCount(messageContext);
        return isCountWithinBounds(count);
    }

    /**
     * Checks whether the given sentence count falls within the configured minimum and maximum bounds.
     *
     * @param count the number of sentences detected.
     * @return true if count is within [min, max], false otherwise.
     */
    private boolean isCountWithinBounds(int count) {
        return this.min <= count && this.max >= count;
    }

    /**
     * Extracts the relevant JSON content and computes the sentence count.
     * <p>
     * If a JsonPath is configured, counts sentences only within the extracted section.
     * Otherwise, counts sentences across the full JSON payload.
     *
     * @param messageContext the current message context.
     * @return the number of sentences detected.
     */
    private int getSentenceCount(MessageContext messageContext) {
        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return 0;
        }

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return countSentences(jsonContent);
        }

        // Check if any extracted value by json path matches the regex pattern
        return countSentences(JsonPath.read(jsonContent, this.jsonPath).toString());
    }

    /**
     * Counts the number of sentences in the given text.
     * <p>
     * Sentences are detected based on terminal punctuation marks (periods, exclamation points, question marks).
     *
     * @param text the text content to analyze.
     * @return the number of sentences found, or zero if the text is empty.
     */
    private int countSentences(String text) {

        if (logger.isDebugEnabled()) {
            logger.debug("SentenceCountGuardrail: Counting sentences in extracted text.");
        }

        if (text == null || text.trim().isEmpty()) {
            return 0;
        }

        // Remove quotes at beginning and end
        String cleanedText = text.replaceAll(SentenceCountGuardrailConstants.TEXT_CLEAN_REGEX, "").trim();

        // Split using regex that detects sentence-ending punctuation
        String[] sentences = cleanedText.split(SentenceCountGuardrailConstants.SENTENCE_SPLIT_REGEX);

        // Handle empty string case after cleaning
        if (sentences.length == 1 && sentences[0].isEmpty()) {
            return 0;
        }
        return sentences.length;
    }

    /**
     * Extracts the full JSON payload from the message context.
     *
     * @param messageContext The Synapse message context.
     * @return The JSON content as a string, or {@code null} if unavailable.
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    /**
     * Builds a JSON object containing assessment details from the guardrail response.
     * This creates a structured representation of the guardrail findings to be included
     * in error messages or for logging purposes.
     *
     * @return A JSON string containing assessment details and guardrail action information
     */
    private String buildAssessmentObject() {
        if (logger.isDebugEnabled()) {
            logger.debug("SentenceCountGuardrail: Building guardrail assessment object.");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(SentenceCountGuardrailConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(SentenceCountGuardrailConstants.ASSESSMENT_REASON, "Guardrail blocked.");
        String message = String.format(
                "Violation of sentence count detected: expected %s %d %s %d sentences.",
                doInvert ? "less than" : "between", this.min, doInvert ? "or more than" : "and", this.max
        );
        assessmentObject.put(SentenceCountGuardrailConstants.ASSESSMENTS, message);

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
