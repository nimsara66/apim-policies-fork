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

    private String schema;
    private String jsonPath = "";
    private boolean doInvert = false;
    private Schema schemaObj;

    /**
     * Initializes the JSONSchemaGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("JSONSchemaGuardrail: Initialized.");
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
            logger.debug("JSONSchemaGuardrail: Beginning guardrail evaluation.");
        }

        try {
            boolean validationResult = validatePayload(messageContext);
            boolean finalResult = doInvert != validationResult;

            if (!finalResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        JSONSchemaGuardrailConstants.ERROR_CODE);
                messageContext.setProperty(JSONSchemaGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(JSONSchemaGuardrailConstants.CUSTOM_HTTP_SC,
                        JSONSchemaGuardrailConstants.ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("JSONSchemaGuardrail: Triggering configured fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(JSONSchemaGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("JSONSchemaGuardrail: Error during guardrail mediation.", e);
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
            logger.debug("JSONSchemaGuardrail: Validating extracted JSON payload.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return validateJsonAgainstSchema(jsonContent);
        }

        // Check if any extracted value by json path matches the regex pattern
        return validateJsonAgainstSchema(JsonPath.read(jsonContent, this.jsonPath).toString());
    }

    /**
     * Performs JSON Schema validation on the provided input string.
     *
     * @param input The JSON string to validate.
     * @return {@code true} if a valid match is found; otherwise, {@code false}.
     */
    private boolean validateJsonAgainstSchema(String input) {

        if (logger.isDebugEnabled()) {
            logger.debug("JSONSchemaGuardrail: Executing schema validation on input.");
        }

        ObjectMapper objectMapper = new ObjectMapper();
        Pattern pattern = Pattern.compile(JSONSchemaGuardrailConstants.JSON_CONTENT_REGEX, Pattern.DOTALL);
        Matcher matcher = pattern.matcher(input);

        while (matcher.find()) {
            String candidate = matcher.group(0);
            try {
                JsonNode node = objectMapper.readTree(candidate);
                this.schemaObj.validate(new JSONObject(node.toString()));
                return true;
            } catch (Exception ignore) {
                // Continue to next match
            }
        }
        return false;
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
            logger.debug("Regex Guardrail assessment creation");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(JSONSchemaGuardrailConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(JSONSchemaGuardrailConstants.ASSESSMENT_REASON, "Guardrail blocked.");
        assessmentObject.put(JSONSchemaGuardrailConstants.ASSESSMENTS,
                "Violation of regular expression: " + schema + " detected.");
        return assessmentObject.toString();
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
}
