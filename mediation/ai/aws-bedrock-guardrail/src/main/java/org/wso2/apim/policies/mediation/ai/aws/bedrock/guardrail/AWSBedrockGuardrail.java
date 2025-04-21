package org.wso2.apim.policies.mediation.ai.aws.bedrock.guardrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Map;
import javax.xml.stream.XMLStreamException;

/**
 * AWS Bedrock Guardrail mediator for API Gateway.
 *
 * This mediator integrates with AWS Bedrock Guardrails service to provide content safety,
 * moderation, and compliance capabilities for API payloads. It intercepts API requests or
 * responses, sends the content to AWS Bedrock Guardrails for evaluation, and can block
 * or modify content based on the guardrail results.
 *
 * Key features:
 * - Content moderation - Detect and filter harmful, offensive, or inappropriate content
 * - PII detection and redaction - Optionally identify and redact personally identifiable information
 * - AI-powered content safety - Leverage AWS Bedrock's advanced AI models for content analysis
 * - Custom guardrails - Use configured AWS Bedrock guardrail id and version
 *
 * This mediator requires AWS credentials and guardrail configuration to be provided through
 * the bedrockConfig property. It communicates with AWS Bedrock using AWS Signature V4
 * authentication and provides the evaluation results back to the API Gateway mediation flow.
 *
 * Usage in mediation sequence example:
 *
 * &lt;amazongpt:bedrockguardrail&gt;
 *     &lt;bedrockConfig&gt;{JSON configuration}&lt;/bedrockConfig&gt;
 *     &lt;redactPII&gt;true&lt;/redactPII&gt;
 * &lt;/amazongpt:bedrockguardrail&gt;
 */
public class AWSBedrockGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(AWSBedrockGuardrail.class);

    private String accessKey;
    private String secretKey;
    // Optional, can be null if not using temporary credentials
    private String sessionToken = null;

    private String region;
    private String guardrailId;
    private String guardrailVersion;
    private String jsonPath = "";
    private int timeout = 60000;
    private boolean redactPII = false;

    /**
     * Initializes the AWSBedrockGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("AWSBedrockGuardrail: Initialized.");
        }
    }

    /**
     * Destroys the AWSBedrockGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Executing AWS Bedrock Guardrail mediation");
        }

        try {
            // Extract the request/ response body from message context
            String jsonContent = AWSBedrockUtils.extractJsonContent(messageContext);

            // Create request payload for AWS Bedrock
            String payload = AWSBedrockUtils.createBedrockRequestPayload(jsonContent, messageContext.isResponse());

            // Construct the Bedrock endpoint URL
            String host = AWSBedrockConstants.BEDROCK_RUNTIME +  "."
                    + region + "." + AWSBedrockConstants.BEDROCK_HOST;
            String uri = "/" + AWSBedrockConstants.GUARDRAIL_SERVICE + "/"
                    + guardrailId + "/" + AWSBedrockConstants.GUARDRAIL_VERSION + "/"
                    + guardrailVersion + "/" + AWSBedrockConstants.GUARDRAIL_CALL;
            String url = AWSBedrockConstants.GUARDRAIL_PROTOCOL + "://" + host + uri;

            if (logger.isDebugEnabled()) {
                logger.debug("AWS Bedrock Guardrail URL: " + url);
            }

            // Generate AWS authentication headers
            Map<String, String> authHeaders = AWSBedrockUtils.generateAWSSignature(
                    host, AWSBedrockConstants.AWS4_METHOD, uri, "", payload, this.accessKey,
                    this.secretKey, this.region, this.sessionToken
            );

            // Make the HTTP POST request to AWS Bedrock
            String response = AWSBedrockUtils.makeBedrockRequest(url, payload, authHeaders, this.timeout);

            return evaluateGuardrailResponse(response, messageContext);
        } catch (Exception e) {
            logger.error("Error during AWS Bedrock Guardrail mediation", e);
        }

        return true;
    }

    /**
     * Evaluates the guardrail response and updates the message context accordingly.
     *
     * @param response The response from AWS Bedrock
     * @param messageContext The current message context
     * @return true if processing should continue, false if guardrail blocked the request
     * @throws IOException If JSON parsing fails
     */
    private boolean evaluateGuardrailResponse(String response, MessageContext messageContext) throws IOException, XMLStreamException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode responseBody = mapper.readTree(response);

        // Check if guardrail intervened
        if (responseBody.has("action") &&
                "GUARDRAIL_INTERVENED".equals(responseBody.get("action").asText())) {

            if (logger.isDebugEnabled()) {
                logger.debug("AWS Bedrock Guardrail intervention detected in response");
            }

            // Check if guardrail blocked the request
            if (responseBody.has("actionReason") &&
                    "Guardrail blocked.".equals(responseBody.get("actionReason").asText())) {

                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        AWSBedrockConstants.BEDROCK_GUARDRAIL_ERROR_CODE);
                messageContext.setProperty(AWSBedrockConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(AWSBedrockConstants.CUSTOM_HTTP_SC,
                        AWSBedrockConstants.BEDROCK_GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject(responseBody);
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                Mediator faultMediator = messageContext.getSequence(AWSBedrockConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        }

        return true; // Continue processing
    }

    /**
     * Builds a JSON object containing assessment details from the guardrail response.
     *
     * @param responseBody The parsed response body
     * @return A JSON object with assessment details
     */
    private String buildAssessmentObject(JsonNode responseBody) {
        JSONObject assessmentObject = new JSONObject();

        if (responseBody.has("assessments")) {
            assessmentObject.put("assessment", new JSONObject(responseBody.get("assessments").get(0).toString()));
        }

        if (responseBody.has("action")) {
            assessmentObject.put("action", responseBody.get("action").asText());
        }

        if (responseBody.has("actionReason")) {
            assessmentObject.put("actionReason", responseBody.get("actionReason").asText());
        }

        return assessmentObject.toString();
    }

    // TODO: Implement PII redaction logic
    private void redactPII(MessageContext messageContext, JsonNode response) {}

    public String getAccessKey() {

        return accessKey;
    }

    public void setAccessKey(String accessKey) {

        this.accessKey = accessKey;
    }

    public String getSecretKey() {

        return secretKey;
    }

    public void setSecretKey(String secretKey) {

        this.secretKey = secretKey;
    }

    public String getSessionToken() {

        return sessionToken;
    }

    public void setSessionToken(String sessionToken) {

        this.sessionToken = sessionToken;
    }

    public String getRegion() {

        return region;
    }

    public void setRegion(String region) {

        this.region = region;
    }

    public String getGuardrailId() {

        return guardrailId;
    }

    public void setGuardrailId(String guardrailId) {

        this.guardrailId = guardrailId;
    }

    public String getGuardrailVersion() {

        return guardrailVersion;
    }

    public void setGuardrailVersion(String guardrailVersion) {

        this.guardrailVersion = guardrailVersion;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public boolean isRedactPII() {

        return redactPII;
    }

    public void setRedactPII(boolean redactPII) {

        this.redactPII = redactPII;
    }

    public int getTimeout() {

        return timeout;
    }

    public void setTimeout(int timeout) {

        this.timeout = timeout;
    }
}
