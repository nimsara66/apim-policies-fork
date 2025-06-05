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

package org.wso2.apim.policies.mediation.ai.aws.bedrock.guardrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import org.apache.axis2.AxisFault;
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

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * AWS Bedrock Guardrail mediator.
 * <p>
 * A mediator that integrates with AWS Bedrock Guardrails to provide request/ response content moderation
 * and PII detection/redaction capabilities for API payloads. This mediator can operate
 * 1. In blocking mode (Bedrock Guardrail decides to block)
 * 2. In masking mode (Bedrock Guardrail decides to mask PII and policy is configured to not redact PII)
 * 3. In redaction mode (Bedrock Guardrail decides to mask PII and policy is configured to redact PII)
 * <p>
 * The mediator supports various authentication methods including direct API keys and
 * role assumption for cross-account access. It can process both request and response payloads,
 * and can be configured to target specific portions of JSON payloads using JsonPath expressions.
 */
public class AWSBedrockGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(AWSBedrockGuardrail.class);

    private String name;
    private String accessKey;
    private String secretKey;
    // Optional, can be null if not using temporary credentials
    private String sessionToken = null;
    // Optional, only for temporary credentials using assumeRole
    private String roleArn;
    private String roleRegion;
    private String roleExternalId;

    private String region;
    private String guardrailId;
    private String guardrailVersion;
    private String jsonPath = "";
    private int timeout = 3000; // Default timeout in milliseconds: 3s
    private boolean passthroughOnError = true;
    private boolean redactPII = false;
    private boolean hideAssessment = false;

    /**
     * Initializes the AWSBedrockGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing AWSBedrockGuardrail.");
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
            logger.debug("Beginning guardrail evaluation");
        }

        try {
            // Transform response if redactPII is disabled and PIIs identified in request
            if (!redactPII && messageContext.isResponse()) {
                identifyPIIAndTransform(messageContext);
                return true; // Continue processing if not redacting PII in response
            }

            // Extract the request/ response body from message context
            String jsonContent = AWSBedrockUtils.extractJsonContent(messageContext);

            if (this.jsonPath != null && !this.jsonPath.trim().isEmpty()) {
                String content = JsonPath.read(jsonContent, this.jsonPath).toString();
                jsonContent = content.replaceAll(AWSBedrockConstants.JSON_CLEAN_REGEX, "").trim();
            }

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
                logger.debug("Sending request to endpoint: " + url);
            }

            Map<String, String> authHeaders;
            if (roleArn != null && !roleArn.isEmpty() && roleRegion != null && !roleRegion.isEmpty()) {

                if (logger.isDebugEnabled()) {
                    logger.debug("Using role-based authentication with ARN: " + roleArn);
                }
                // Generate AWS authentication headers using AssumeRole
                authHeaders = AWSBedrockUtils.generateAWSSignatureUsingAssumeRole(
                        host, AWSBedrockConstants.AWS4_METHOD, uri, "", payload, this.accessKey,
                        this.secretKey, this.region, this.sessionToken, this.roleArn, this.roleRegion,
                        this.roleExternalId
                );
            } else {

                if (logger.isDebugEnabled()) {
                    logger.debug("Using direct AWS credentials for authentication");
                }
                // Generate AWS authentication headers
                authHeaders = AWSBedrockUtils.generateAWSSignature(
                        host, AWSBedrockConstants.AWS4_METHOD, AWSBedrockConstants.BEDROCK_SERVICE, uri, "",
                        payload, this.accessKey,
                        this.secretKey, this.region, this.sessionToken
                );
            }

            // Make the HTTP POST request to AWS Bedrock
            String response = AWSBedrockUtils.makeBedrockRequest(url, payload, authHeaders,
                    this.timeout, passthroughOnError);

            return evaluateGuardrailResponse(response, messageContext);
        } catch (Exception e) {
            logger.error("Error during guardrail evaluation", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    AWSBedrockConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Error occurred during AWSBedrockGuardrail mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);
        }

        return false; // Stop further processing
    }

    private void identifyPIIAndTransform(MessageContext messageContext) throws AxisFault {
        Map<String, String> maskedPIIEntities = (Map<String, String>) messageContext.getProperty("PII_ENTITIES");

        boolean foundMasked = false;
        String maskedContent = AWSBedrockUtils.extractJsonContent(messageContext);
        if (maskedPIIEntities != null) {
            for (Map.Entry<String, String> entry : maskedPIIEntities.entrySet()) {
                String original = entry.getKey();
                String placeholder = entry.getValue();
                maskedContent = maskedContent.replace(placeholder, original);
                foundMasked = true;
            }
        }

        if (foundMasked) {
            if (logger.isDebugEnabled()) {
                logger.debug("PII entities found and in the request.Replacing masked PIIs back in response.");
            }

            // Update the message context with the masked content
            org.apache.axis2.context.MessageContext axis2MC =
                    ((Axis2MessageContext) messageContext).getAxis2MessageContext();
            JsonUtil.getNewJsonPayload(axis2MC, maskedContent, true, true);
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("No PII entities found in the request. No response transformation needed.");
            }
        }
    }

    /**
     * Evaluates the guardrail response from AWS Bedrock and takes appropriate action.
     * This method processes three main scenarios:
     * 1. Guardrail intervention that blocks the request
     * 2. Guardrail intervention that masks PII in the output
     * 3. PII detection with optional redaction (when redactPII is enabled)
     *
     * @param response The JSON response string from AWS Bedrock
     * @param messageContext The current message context being processed
     * @return {@code true} if processing should continue, {@code false} if guardrail blocked the request
     * @throws IOException If JSON parsing fails
     */
    private boolean evaluateGuardrailResponse(String response, MessageContext messageContext) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode responseBody = mapper.readTree(response);

        // Check if guardrail intervened
        if (responseBody.has(AWSBedrockConstants.ASSESSMENT_ACTION) &&
                "GUARDRAIL_INTERVENED".equals(responseBody.get(AWSBedrockConstants.ASSESSMENT_ACTION).asText())) {

            if (logger.isDebugEnabled()) {
                logger.debug("AWS Bedrock Guardrail has intervened in the "
                        + (messageContext.isResponse() ? "response." : "request."));
            }

            // Check if guardrail blocked the request
            if (responseBody.has(AWSBedrockConstants.ASSESSMENT_REASON) &&
                    "Guardrail blocked.".equals(responseBody.get(AWSBedrockConstants.ASSESSMENT_REASON).asText())) {

                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        AWSBedrockConstants.GUARDRAIL_APIM_EXCEPTION_CODE);
                messageContext.setProperty(AWSBedrockConstants.ERROR_TYPE, AWSBedrockConstants.AWS_BEDROCK_GUARDRAIL);
                messageContext.setProperty(AWSBedrockConstants.CUSTOM_HTTP_SC,
                        AWSBedrockConstants.GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject(responseBody);
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("Triggering fault sequence");
                }

                Mediator faultMediator = messageContext.getSequence(AWSBedrockConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }

            boolean bedrockDecidedToMask = responseBody.has(AWSBedrockConstants.ASSESSMENT_REASON) &&
                    "Guardrail masked.".equals(responseBody.get(AWSBedrockConstants.ASSESSMENT_REASON).asText());
            // Check if guardrail masked any PII and redactPII is disabled
            if (!redactPII && !messageContext.isResponse() && bedrockDecidedToMask) {

                if (logger.isDebugEnabled()) {
                    logger.debug("PII masking applied by Bedrock service. Masking PII in request.");
                }

                JsonNode sensitiveInformationPolicy = responseBody.path(AWSBedrockConstants.ASSESSMENTS).path(0)
                        .get(AWSBedrockConstants.BEDROCK_GUARDRAIL_SIP);
                if (sensitiveInformationPolicy == null) return true;

                String jsonContent = AWSBedrockUtils.extractJsonContent(messageContext);
                String initialPayload = jsonContent;
                AtomicInteger counter = new AtomicInteger();
                Map<String, String> maskedPIIEntities = new LinkedHashMap<>();

                if (this.jsonPath != null && !this.jsonPath.trim().isEmpty()) {
                    String content = JsonPath.read(jsonContent, this.jsonPath).toString();
                    jsonContent = content.replaceAll(AWSBedrockConstants.JSON_CLEAN_REGEX, "").trim();
                }

                // Process piiEntities
                JsonNode piiEntities = sensitiveInformationPolicy.get(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_ENTITIES);
                if (piiEntities != null && piiEntities.isArray()) {
                    for (JsonNode entity : piiEntities) {
                        // Check if the entity action is configured to anonymized in AWS bedrock
                        if ("ANONYMIZED".equals(entity.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_ACTION).asText())) {
                            String match = entity.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_MATCH).asText();
                            String type = entity.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_TYPE).asText();
                            String replacement = "<" + type + "_" + generateHexId(counter) + ">";
                            jsonContent = AWSBedrockUtils
                                    .replaceExactMatch(jsonContent, match, replacement);
                            maskedPIIEntities.put(match, replacement);
                        }
                    }
                }

                // Process regexes
                JsonNode regexes = sensitiveInformationPolicy.get(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_REGEXES);
                if (regexes != null && regexes.isArray()) {
                    for (JsonNode regexNode : regexes) {
                        // Check if the regex action is configured to anonymized in AWS bedrock
                        if ("ANONYMIZED".equals(regexNode.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_ACTION).asText())) {
                            String match = regexNode.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_MATCH).asText();
                            String name = regexNode.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_NAME).asText();
                            String replacement = "<" + name.toUpperCase() + "_" + generateHexId(counter) + ">";
                            jsonContent = AWSBedrockUtils
                                    .replaceExactMatch(jsonContent, match, replacement);
                            maskedPIIEntities.put(match, replacement);
                        }
                    }
                }

                if (!maskedPIIEntities.isEmpty()) {
                    messageContext.setProperty("PII_ENTITIES", maskedPIIEntities);
                }

                if (this.jsonPath != null && !this.jsonPath.trim().isEmpty()) {
                    DocumentContext ctx = JsonPath.parse(initialPayload);
                    ctx.set(this.jsonPath, jsonContent);
                    jsonContent = ctx.jsonString();
                }

                org.apache.axis2.context.MessageContext axis2MC =
                        ((Axis2MessageContext) messageContext).getAxis2MessageContext();
                JsonUtil.getNewJsonPayload(axis2MC, jsonContent,
                        true, true);
            }

            // Check if guardrail masked any PII and redactPII is enabled
            if (redactPII && bedrockDecidedToMask) {

                if (logger.isDebugEnabled()) {
                    logger.debug("PII masking applied by Bedrock service. Redacting PII in "
                            + (messageContext.isResponse()? "response." : "request."));
                }

                JsonNode output = responseBody.get(AWSBedrockConstants.BEDROCK_GUARDRAIL_OUTPUT);
                if (output != null && output.isArray() && !output.isEmpty()) {
                    JsonNode firstOutput = output.get(0);
                    if (firstOutput.has(AWSBedrockConstants.BEDROCK_GUARDRAIL_TEXT)) {
                        String text = firstOutput.get(AWSBedrockConstants.BEDROCK_GUARDRAIL_TEXT).asText();

                        if (this.jsonPath != null && !this.jsonPath.trim().isEmpty()) {
                            String jsonContent = AWSBedrockUtils.extractJsonContent(messageContext);
                            DocumentContext ctx = JsonPath.parse(jsonContent);
                            ctx.set(this.jsonPath, text);
                            text = ctx.jsonString();
                        }

                        org.apache.axis2.context.MessageContext axis2MC =
                                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
                        JsonUtil.getNewJsonPayload(axis2MC, text,
                                true, true);
                    }
                }
            }
        }

        return true; // Continue processing
    }

    private static String generateHexId(AtomicInteger counter) {
        int count = counter.getAndIncrement();
        return String.format("%04x", count); // 4-digit hex string, zero-padded
    }

    /**
     * Builds a JSON object containing assessment details from the guardrail response.
     * This creates a structured representation of the guardrail findings to be included
     * in error messages or for logging purposes.
     *
     * @param responseBody The parsed JSON response from AWS Bedrock
     * @return A JSON string containing assessment details and guardrail action information
     */
    private String buildAssessmentObject(JsonNode responseBody) {
        JSONObject assessmentObject = new JSONObject();

        if (responseBody.has(AWSBedrockConstants.ASSESSMENT_ACTION)) {
            assessmentObject.put(AWSBedrockConstants.ASSESSMENT_ACTION,
                    responseBody.get(AWSBedrockConstants.ASSESSMENT_ACTION).asText());
        }

        if (responseBody.has(AWSBedrockConstants.ASSESSMENT_REASON)) {
            assessmentObject.put(AWSBedrockConstants.ASSESSMENT_REASON,
                    responseBody.get(AWSBedrockConstants.ASSESSMENT_REASON).asText());
        }

        assessmentObject.put(AWSBedrockConstants.INTERVENING_GUARDRAIL, this.getName());

        if (!hideAssessment && responseBody.has(AWSBedrockConstants.ASSESSMENTS)) {
            JsonNode assessmentNode = responseBody.get(AWSBedrockConstants.ASSESSMENTS).get(0);

            // Remove 'invocationMetrics' if it exists
            if (assessmentNode.isObject()) {
                ((ObjectNode) assessmentNode).remove("invocationMetrics");
            }

            // Convert JsonNode to JSONObject
            JSONObject assessmentJson = new JSONObject(assessmentNode.toString());
            assessmentObject.put(AWSBedrockConstants.ASSESSMENTS, assessmentJson);
        }

        return assessmentObject.toString();
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

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

    public String getRoleArn() {

        return roleArn;
    }

    public void setRoleArn(String roleArn) {

        this.roleArn = roleArn;
    }

    public String getRoleRegion() {

        return roleRegion;
    }

    public void setRoleRegion(String roleRegion) {

        this.roleRegion = roleRegion;
    }

    public String getRoleExternalId() {

        return roleExternalId;
    }

    public void setRoleExternalId(String roleExternalId) {

        this.roleExternalId = roleExternalId;
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

    public boolean isPassthroughOnError() {

        return passthroughOnError;
    }

    public void setPassthroughOnError(boolean passthroughOnError) {

        this.passthroughOnError = passthroughOnError;
    }

    public boolean isHideAssessment() {

        return hideAssessment;
    }

    public void setHideAssessment(boolean hideAssessment) {

        this.hideAssessment = hideAssessment;
    }
}
