package org.wso2.apim.policies.mediation.ai.url.guardrail;

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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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
public class URLGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(URLGuardrail.class);

    private String jsonPath = "";
    private boolean doInvert = false;

    /**
     * Initializes the URLGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("URLGuardrail: Initialized.");
        }
    }

    /**
     * Destroys the URLGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Executing URLGuardrail mediation");
        }

        try {
            boolean validationResult = validatePayload(messageContext);
            boolean finalResult = doInvert != validationResult;

            if (!finalResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        JSONSchemaGuardrailConstants.JSON_SCHEMA_GUARDRAIL_ERROR_CODE);
                messageContext.setProperty(JSONSchemaGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(JSONSchemaGuardrailConstants.CUSTOM_HTTP_SC,
                        JSONSchemaGuardrailConstants.JSON_SCHEMA_GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("Initiating JSONSchemaGuardrail fault sequence");
                }

                Mediator faultMediator = messageContext.getSequence(JSONSchemaGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Error during JSONSchemaGuardrail mediation", e);
        }

        return true;
    }

    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating URLGuardrail payload");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return validateJsonAgainstURL(jsonContent);
        }

        // Check if any extracted value by json path matches the regex pattern
        return validateJsonAgainstURL(JsonPath.read(jsonContent, this.jsonPath).toString());
    }

    /**
     * Validates a JSON string against the configured schema.
     */
    private boolean validateJsonAgainstURL(String input) {

        if (logger.isDebugEnabled()) {
            logger.debug("URLGuardrail validating content urls");
        }

        Pattern urlPattern = Pattern.compile("https?://[^\\s,\"'{}\\[\\]]+");
        Matcher urlMatcher = urlPattern.matcher(input);

        List<String> urls = new ArrayList<>();
        while (urlMatcher.find()) {
            urls.add(urlMatcher.group(0));
        }
        return false;
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
        assessmentObject.put("assessments", "Violation of regular expression: " + schema + " detected.");
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
