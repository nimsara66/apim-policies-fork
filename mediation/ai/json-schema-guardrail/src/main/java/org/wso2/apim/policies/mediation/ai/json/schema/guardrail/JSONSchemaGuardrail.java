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

package org.wso2.apim.policies.mediation.ai.json.schema.guardrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.lang.StringEscapeUtils;
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
import org.everit.json.schema.Schema;
import org.everit.json.schema.loader.SchemaLoader;
import org.json.JSONObject;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * JSON Schema Guardrail mediator.
 * <p>
 * A Synapse mediator that validates incoming JSON payloads against a specified JSON Schema.
 * Supports selective validation using JsonPath expressions and inversion logic to determine
 * blocking conditions. Designed to enforce data quality and compliance checks at API gateway level.
 * <p>
 * If the payload fails validation (or passes when inversion is enabled), the mediator
 * triggers a configured fault sequence to handle the violation.
 */
public class JSONSchemaGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(JSONSchemaGuardrail.class);

    private String name;
    private String schema;
    private String jsonPath = "";
    private boolean doInvert = false;
    private boolean hideAssessment = false;
    private Schema schemaObj;

    /**
     * Initializes the JSONSchemaGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing JSONSchemaGuardrail");
        }
    }

    /**
     * Destroys the JSONSchemaGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    /**
     * Executes the JSON schema validation logic against the incoming message payload.
     * <p>
     * If the payload fails validation (or passes, when inverted), a fault sequence is triggered,
     * and the mediation flow is interrupted.
     *
     * @param messageContext The Synapse message context containing the payload.
     * @return {@code true} to continue mediation flow, {@code false} to invoke a fault sequence.
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Beginning guardrail evaluation.");
        }

        try {
            boolean doTriggerGuardrailError = validatePayload(messageContext);

            if (doTriggerGuardrailError) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        JSONSchemaGuardrailConstants.GUARDRAIL_APIM_EXCEPTION_CODE);
                messageContext.setProperty(JSONSchemaGuardrailConstants.ERROR_TYPE,
                        JSONSchemaGuardrailConstants.JSON_SCHEMA_GUARDRAIL);
                messageContext.setProperty(JSONSchemaGuardrailConstants.CUSTOM_HTTP_SC,
                        JSONSchemaGuardrailConstants.GUARDRAIL_ERROR_CODE);

                if (logger.isDebugEnabled()) {
                    logger.debug("Triggering configured fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(JSONSchemaGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Error during guardrail mediation.", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    JSONSchemaGuardrailConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Error occurred during JSONSchemaGuardrail mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);
            return false; // Stop further processing
        }

        return true;
    }

    /**
     * Validates the extracted JSON content against the configured schema.
     *
     * @param messageContext The Synapse message context.
     * @return {@code true} if the payload matches the schema; otherwise, {@code false}.
     */
    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating extracted JSON payload.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return validateJsonAgainstSchema(jsonContent, messageContext);
        }

        // Check if any extracted value by json path matches the regex pattern
        return validateJsonAgainstSchema(JsonPath.read(jsonContent, this.jsonPath).toString(), messageContext);
    }

    /**
     * Performs JSON Schema validation on the provided input string.
     *
     * @param input The JSON string to validate.
     * @return {@code true} if a valid match is found; otherwise, {@code false}.
     */
    private boolean validateJsonAgainstSchema(String input, MessageContext messageContext) {

        if (logger.isDebugEnabled()) {
            logger.debug("Executing schema validation on input.");
        }

        ObjectMapper objectMapper = new ObjectMapper();
        Pattern pattern = Pattern.compile(JSONSchemaGuardrailConstants.JSON_CONTENT_REGEX, Pattern.DOTALL);
        Matcher matcher = pattern.matcher(input);

        boolean matchedAndValid = false;

        while (matcher.find()) {
            String candidate = matcher.group(0);
            try {
                String unescapedCandidate = StringEscapeUtils.unescapeJava(candidate);
                JsonNode node = objectMapper.readTree(unescapedCandidate);
                this.schemaObj.validate(new JSONObject(node.toString()));
                matchedAndValid =  true;
                break; // Exit loop on first valid match
            } catch (Exception ignore) {
                // Continue to next match
            }
        }

        boolean finalResult = doInvert != matchedAndValid;
        if (!finalResult) {
            // Early build assessment details
            String assessmentObject = buildAssessmentObject(input, messageContext.isResponse());
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);
        }

        return !finalResult;
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
    private String buildAssessmentObject(String content, boolean isResponse) {
        if (logger.isDebugEnabled()) {
            logger.debug("Building guardrail assessment object.");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(JSONSchemaGuardrailConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(JSONSchemaGuardrailConstants.INTERVENING_GUARDRAIL, this.getName());
        assessmentObject.put(JSONSchemaGuardrailConstants.DIRECTION, isResponse? "RESPONSE" : "REQUEST");
        assessmentObject.put(JSONSchemaGuardrailConstants.ASSESSMENT_REASON,
                "Violation of enforced JSON schema detected.");

        if (!this.hideAssessment) {
            String message = "The inspected response payload content: " + content
                    + " does not satisfy the JSON schema: " + schema;
            assessmentObject.put(JSONSchemaGuardrailConstants.ASSESSMENTS, message);
        }
        return assessmentObject.toString();
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getSchema() {

        return schema;
    }

    public void setSchema(String schema) {

        this.schema = schema;

        try {
            this.schemaObj = SchemaLoader.load(new JSONObject(schema));
        } catch (PatternSyntaxException e) {
            logger.error("Invalid JSON schema: " + schema, e);
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

    public boolean isHideAssessment() {

        return hideAssessment;
    }

    public void setHideAssessment(boolean hideAssessment) {

        this.hideAssessment = hideAssessment;
    }
}
