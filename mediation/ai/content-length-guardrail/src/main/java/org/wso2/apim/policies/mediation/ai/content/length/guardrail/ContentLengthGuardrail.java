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

package org.wso2.apim.policies.mediation.ai.content.length.guardrail;

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

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Content Length Guardrail mediator.
 * <p>
 * A Synapse mediator that validates the content length of incoming payloads. This guardrail ensures
 * that the size of the request payload (in bytes) adheres to the defined minimum and maximum content
 * length bounds. It helps enforce payload size restrictions, ensuring that the message size falls
 * within the acceptable limits, enhancing system performance and security by preventing oversized payloads.
 * <p>
 * The validator supports JSONPath expressions to apply validation rules to specific sections of the payload.
 * If no JSONPath is specified, the entire payload is validated against the content length constraints.
 * The content length is calculated based on the UTF-8 byte size of the message.
 * <p>
 * If the validation fails, the mediator interrupts message processing, sets error details in the message context,
 * and triggers a fault sequence. The response includes a structured assessment object with metadata about
 * the content length violation, providing clear information about the size limits and the specific rule violation.
 */
public class ContentLengthGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(ContentLengthGuardrail.class);

    private String name;
    private int min;
    private int max;
    private String jsonPath = "";
    private boolean doInvert = false;
    private boolean buildAssessment = true;

    /**
     * Initializes the ContentLengthGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("ContentLengthGuardrail: Initialized.");
        }
    }

    /**
     * Destroys the ContentLengthGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    /**
     * The entry point for mediation. This method validates the content length of the incoming payload
     * based on the configured bounds. If the content length is within the bounds, processing continues;
     * otherwise, a fault sequence is triggered and further processing is stopped.
     *
     * @param messageContext The Synapse message context, which contains the request payload.
     * @return {@code true} if validation is successful and processing should continue; {@code false}
     *         if validation fails and further processing should be stopped.
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("ContentLengthGuardrail: Starting mediation.");
        }

        try {
            boolean validationResult = validatePayload(messageContext);
            boolean finalResult = doInvert != validationResult;

            if (!finalResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        ContentLengthGuardrailConstants.GUARDRAIL_APIM_EXCEPTION_CODE);
                messageContext.setProperty(ContentLengthGuardrailConstants.ERROR_TYPE,
                        ContentLengthGuardrailConstants.CONTENT_LENGTH_GUARDRAIL);
                messageContext.setProperty(ContentLengthGuardrailConstants.CUSTOM_HTTP_SC,
                        ContentLengthGuardrailConstants.GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("ContentLengthGuardrail: Validation failed - triggering fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(ContentLengthGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("ContentLengthGuardrail: Error during mediation", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    ContentLengthGuardrailConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Error occurred during ContentLengthGuardrail mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);
            return false;
        }

        return true;
    }

    /**
     * Validates the payload by extracting JSON and calculating content length.
     *
     * @param messageContext the Synapse message context
     * @return {@code true} if the byte length of the input is between {@code min} and {@code max} (inclusive),
     * {@code false} otherwise.
     */
    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("ContentLengthGuardrail: Validating payload.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return isCountWithinBounds("");
        }

        // If no JSON path is specified, apply validation to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return isCountWithinBounds(jsonContent);
        }

        String content = JsonPath.read(jsonContent, this.jsonPath).toString();

        // Remove quotes at beginning and end
        String cleanedText = content.replaceAll(ContentLengthGuardrailConstants.JSON_CLEAN_REGEX, "").trim();

        return isCountWithinBounds(cleanedText);
    }

    /**
     * Validates whether the UTF-8 encoded byte length of the provided input string
     * is within the configured minimum and maximum content length bounds.
     *
     * <p>This method is typically used to enforce HTTP content length restrictions
     * based on the number of bytes the input would consume in transmission.</p>
     *
     * @param input The string input to evaluate.
     * @return {@code true} if the byte length of the input is between {@code min} and {@code max} (inclusive),
     * {@code false} otherwise.
     */
    private boolean isCountWithinBounds(String input) {
        if (logger.isDebugEnabled()) {
            logger.debug("ContentLengthGuardrail: Validating extracted content.");
        }

        int byteLength = input.getBytes(StandardCharsets.UTF_8).length;
        return (byteLength >= min && byteLength <= max);
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
            logger.debug("ContentLengthGuardrail: Building assessment");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(ContentLengthGuardrailConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(ContentLengthGuardrailConstants.INTERVENING_GUARDRAIL, this.getName());
        assessmentObject.put(ContentLengthGuardrailConstants.ASSESSMENT_REASON,
                "Violation of content length detected.");

        if (this.buildAssessment) {
            String message = String.format(
                    "Expected %s %d %s %d bytes.",
                    this.doInvert
                            ? "less than"
                            : "between", this.min,
                    this.doInvert
                            ? "or more than"
                            : "and", this.max
            );

            assessmentObject.put(ContentLengthGuardrailConstants.ASSESSMENTS, message);
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

    public boolean isDoInvert() {

        return doInvert;
    }

    public void setDoInvert(boolean doInvert) {

        this.doInvert = doInvert;
    }

    public boolean isBuildAssessment() {

        return buildAssessment;
    }

    public void setBuildAssessment(boolean buildAssessment) {

        this.buildAssessment = buildAssessment;
    }
}
