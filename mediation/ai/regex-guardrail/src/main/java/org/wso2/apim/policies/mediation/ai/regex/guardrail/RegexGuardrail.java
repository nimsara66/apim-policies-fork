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
            logger.debug("Executing RegexGuardrail mediation");
        }

        try {
            boolean validationResult = validatePayload(messageContext);
            boolean finalResult = doInvert != validationResult;

            if (!finalResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        RegexGuardrailConstants.REGEX_GUARDRAIL_ERROR_CODE);
                messageContext.setProperty(RegexGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(RegexGuardrailConstants.CUSTOM_HTTP_SC,
                        RegexGuardrailConstants.REGEX_GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("Initiating RegexGuardrail fault sequence");
                }

                Mediator faultMediator = messageContext.getSequence(RegexGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Error during RegexGuardrail mediation", e);
        }

        return true;
    }

    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating RegexGuardrail payload");
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
        assessmentObject.put("assessments", "Violation of regular expression: " + regex + " detected.");
        return assessmentObject.toString();
    }

    public String getRegex() {

        return regex;
    }

    public void setRegex(String regex) {

        this.regex = regex;

        try {
            this.pattern = Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            logger.error("Invalid regex pattern: " + regex, e);
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
