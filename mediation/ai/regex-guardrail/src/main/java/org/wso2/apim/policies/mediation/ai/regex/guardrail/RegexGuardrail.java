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

package org.wso2.apim.policies.mediation.ai.regex.guardrail;

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

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Regex Guardrail mediator.
 * <p>
 * A mediator that performs regex-based validation on payloads according to specified patterns.
 * This guardrail can be configured with JSON path expressions to target specific parts of JSON payloads
 * and apply regex pattern validation against them. The validation result can be inverted if needed.
 * <p>
 * When validation fails, the mediator triggers a fault sequence and enriches the message context
 * with appropriate error details.
 */
public class RegexGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(RegexGuardrail.class);

    private String regex;
    private String jsonPath = "";
    private boolean doInvert = false;
    private Pattern pattern;

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
            logger.debug("RegexGuardrail: Beginning payload validation.");
        }

        try {
            boolean validationResult = validatePayload(messageContext);
            boolean finalResult = doInvert != validationResult;

            if (!finalResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        RegexGuardrailConstants.ERROR_CODE);
                messageContext.setProperty(RegexGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(RegexGuardrailConstants.CUSTOM_HTTP_SC,
                        RegexGuardrailConstants.ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("RegexGuardrail: Validation failed - triggering fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(RegexGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("RegexGuardrail: Exception occurred during mediation.", e);
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
    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("RegexGuardrail: Extracting content for validation.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return pattern.matcher(jsonContent).find();
        }

        String content = JsonPath.read(jsonContent, this.jsonPath).toString();

        // Remove quotes at beginning and end
        String cleanedText = content.replaceAll("^\"|\"$", "").trim();

        // Check if any extracted value by json path matches the regex pattern
        return pattern.matcher(cleanedText).find();
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

        assessmentObject.put(RegexGuardrailConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(RegexGuardrailConstants.ASSESSMENT_REASON, "Guardrail blocked.");
        assessmentObject.put(RegexGuardrailConstants.ASSESSMENTS,
                "Violation of regular expression: " + regex + " detected.");
        return assessmentObject.toString();
    }

    public String getRegex() {

        return regex;
    }

    public void setRegex(String regex) {

        this.regex = regex;

        try {
            this.pattern = Pattern.compile(regex);
            if (logger.isDebugEnabled()) {
                logger.debug("RegexGuardrail: Regex pattern compiled successfully: " + regex);
            }
        } catch (PatternSyntaxException e) {
            logger.error("RegexGuardrail: Invalid regex pattern: " + regex, e);
        }
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
