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
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.dto.ai.AWSBedrockGuardrailsConfigurationDTO;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;

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
    private static final APIManagerConfiguration apimConfig =
            ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService()
                    .getAPIManagerConfiguration();

    private String name;

    private String accessKey;
    private String secretKey;
    // Optional, can be null if not using temporary credentials
    private String sessionToken;
    // Optional, only for temporary credentials using assumeRole
    private String roleArn;
    private String roleRegion;
    private String roleExternalId;

    private String region;
    private String guardrailId;
    private String guardrailVersion;
    private String jsonPath = "";
    private boolean passthroughOnError = false;
    private boolean redactPII = false;
    private boolean showAssessment = false;

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

        AWSBedrockGuardrailsConfigurationDTO config = apimConfig.getAwsBedrockGuardrailsConfigurationDTO();

        if (config.getAccessKey() == null || config.getSecretKey() == null) {
            throw new IllegalArgumentException(
                    "Invalid Azure Content Safety configuration: Please verify that the API key and endpoint " +
                            "specified in deployment.toml are correct.");
        }

        this.accessKey = config.getAccessKey();
        this.secretKey = config.getSecretKey();
        this.sessionToken = config.getSessionToken();
        this.roleArn = config.getRoleArn();
        this.roleRegion = config.getRoleRegion();
        this.roleExternalId = config.getRoleExternalId();
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
                jsonContent = content.replaceAll(AWSBedrockConstants.TEXT_CLEAN_REGEX, "").trim();
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
            String response = AWSBedrockUtils.makeBedrockRequest(url, payload, authHeaders);

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
     * Evaluates the AWS Bedrock Guardrail response and applies appropriate actions based on its assessment.
     * This includes handling full intervention, PII masking, and conditional redaction.
     *
     * @param response        JSON response string from AWS Bedrock
     * @param messageContext  Current Synapse message context
     * @return true if processing should continue; false if guardrail intervention requires blocking the request
     * @throws IOException if the response cannot be parsed
     */
    private boolean evaluateGuardrailResponse(String response, MessageContext messageContext) throws IOException, APIManagementException {

        if (response.isEmpty()) {
            if (isPassthroughOnError()) return true;

            setErrorProperties(messageContext,
                    "AWS Bedrock Guardrails API is unreachable or returned an invalid response.");
            triggerFaultSequence(messageContext);
            return false;
        }

        JsonNode responseBody = new ObjectMapper().readTree(response);

        // Check if guardrail intervened
        if (responseBody.has(AWSBedrockConstants.ASSESSMENT_ACTION) &&
                "GUARDRAIL_INTERVENED".equals(responseBody.get(AWSBedrockConstants.ASSESSMENT_ACTION).asText())) {

            if (logger.isDebugEnabled()) {
                logger.debug("AWS Bedrock Guardrail has intervened in the "
                        + (messageContext.isResponse() ? "response." : "request."));
            }

            String reason = responseBody.path(AWSBedrockConstants.ASSESSMENT_REASON).asText();
            boolean isResponse = messageContext.isResponse();

            // Check if guardrail blocked the request
            if ("Guardrail blocked.".equals(reason)) {
                setErrorProperties(messageContext,
                        buildAssessmentObject(responseBody));
                triggerFaultSequence(messageContext);
                return false;
            }

            boolean maskApplied = "Guardrail masked.".equals(reason);

            // Check if guardrail masked any PII and redactPII is disabled
            if (!redactPII && !isResponse && maskApplied) {
                if (logger.isDebugEnabled()) {
                    logger.debug("PII masking applied by Bedrock service. Masking PII in request.");
                }

                JsonNode sipNode = responseBody.path(AWSBedrockConstants.ASSESSMENTS).path(0)
                        .get(AWSBedrockConstants.BEDROCK_GUARDRAIL_SIP);
                if (sipNode != null) {
                    maskPIIEntities(sipNode, messageContext);
                }

                return true; // Continue processing after masking PII
            }

            if (redactPII && maskApplied) {
                redactPIIEntities(responseBody, messageContext);

                return true; // Continue processing after redacting PII
            }
        }

        if (responseBody.has(AWSBedrockConstants.ASSESSMENT_ACTION) &&
                "NONE".equals(responseBody.get(AWSBedrockConstants.ASSESSMENT_ACTION).asText())) {

            return true; // No intervention, continue processing
        }

        // Should not reach here
        throw new APIManagementException("AWS Bedrock Guardrails returned unexpected response: " + response);
    }

    private void setErrorProperties(MessageContext context, String detail) {
        context.setProperty(SynapseConstants.ERROR_CODE, AWSBedrockConstants.GUARDRAIL_APIM_EXCEPTION_CODE);
        context.setProperty(AWSBedrockConstants.ERROR_TYPE, AWSBedrockConstants.AWS_BEDROCK_GUARDRAIL);
        context.setProperty(AWSBedrockConstants.CUSTOM_HTTP_SC, AWSBedrockConstants.GUARDRAIL_ERROR_CODE);

        JSONObject assessment = new JSONObject();
        assessment.put(AWSBedrockConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessment.put(AWSBedrockConstants.INTERVENING_GUARDRAIL, this.name);
        assessment.put(AWSBedrockConstants.DIRECTION, context.isResponse() ? "RESPONSE" : "REQUEST");
        assessment.put(AWSBedrockConstants.ASSESSMENT_REASON, "Violation of AWS Bedrock Guardrails detected.");
        if (showAssessment) {
            assessment.put(AWSBedrockConstants.ASSESSMENTS, detail.startsWith("{") && detail.endsWith("}")
                    ? new JSONObject(detail)
                    : detail);
        }
        context.setProperty(SynapseConstants.ERROR_MESSAGE, assessment.toString());
    }

    private void triggerFaultSequence(MessageContext context) {
        if (logger.isDebugEnabled()) logger.debug("Triggering fault sequence");
        Mediator faultMediator = context.getSequence(AWSBedrockConstants.FAULT_SEQUENCE_KEY);
        if (faultMediator == null) {
            context.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Violation of " + name + " detected.");
            faultMediator = context.getFaultSequence(); // Fall back to default error sequence
        }
        faultMediator.mediate(context);
    }

    private void maskPIIEntities(JsonNode sipNode, MessageContext context) throws AxisFault {
        if (logger.isDebugEnabled()) {
            logger.debug("PII masking applied by Bedrock service. Masking PII in "
                    + (context.isResponse()? "response." : "request."));
        }

        String payload = AWSBedrockUtils.extractJsonContent(context);
        String originalPayload = payload;
        Map<String, String> maskedPII = new LinkedHashMap<>();
        AtomicInteger counter = new AtomicInteger();

        if (this.jsonPath != null && !this.jsonPath.trim().isEmpty()) {
            payload = JsonPath.read(payload, this.jsonPath).toString()
                    .replaceAll(AWSBedrockConstants.TEXT_CLEAN_REGEX, "").trim();
        }

        String updatedPayload = processPIIEntities(sipNode
                .get(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_ENTITIES), payload, maskedPII, counter);
        updatedPayload = processPIIEntities(sipNode.get(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_REGEXES),
                updatedPayload, maskedPII, counter);

        if (!maskedPII.isEmpty()) {
            context.setProperty("PII_ENTITIES", maskedPII);
        }

        if (this.jsonPath != null && !this.jsonPath.trim().isEmpty()) {
            DocumentContext ctx = JsonPath.parse(originalPayload);
            ctx.set(this.jsonPath, updatedPayload);
            updatedPayload = ctx.jsonString();
        }

        JsonUtil.getNewJsonPayload(
                ((Axis2MessageContext) context).getAxis2MessageContext(),
                updatedPayload, true, true);
    }

    private String processPIIEntities(JsonNode entities, String payload,
                                    Map<String, String> maskedPII, AtomicInteger counter) {
        if (entities == null || !entities.isArray()) return payload;

        for (JsonNode entity : entities) {
            if ("ANONYMIZED".equals(entity.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_ACTION).asText())) {
                String match = entity.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_MATCH).asText();

                // Skip if already processed
                if (maskedPII.containsKey(match)) {
                    continue;
                }

                String type = entity.has(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_TYPE)
                        ? entity.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_TYPE).asText()
                        : entity.path(AWSBedrockConstants.BEDROCK_GUARDRAIL_PII_NAME).asText().toUpperCase();
                String replacement = type + "_" + generateHexId(counter);
                payload = AWSBedrockUtils.replaceExactMatch(payload, match, replacement);
                maskedPII.put(match, replacement);
            }
        }
        return payload;
    }

    private void redactPIIEntities(JsonNode responseBody, MessageContext context) throws AxisFault {
        if (logger.isDebugEnabled()) {
            logger.debug("PII masking applied by Bedrock service. Redacting PII in "
                    + (context.isResponse()? "response." : "request."));
        }

        JsonNode output = responseBody.get(AWSBedrockConstants.BEDROCK_GUARDRAIL_OUTPUT);
        if (output == null || !output.isArray() || output.isEmpty()) return;

        String text = output.get(0).path(AWSBedrockConstants.BEDROCK_GUARDRAIL_TEXT).asText("");
        if (this.jsonPath != null && !this.jsonPath.trim().isEmpty()) {
            String jsonContent = AWSBedrockUtils.extractJsonContent(context);
            DocumentContext ctx = JsonPath.parse(jsonContent);
            ctx.set(this.jsonPath, text);
            text = ctx.jsonString();
        }

        JsonUtil.getNewJsonPayload(
                ((Axis2MessageContext) context).getAxis2MessageContext(),
                text, true, true);
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
        JsonNode assessments = responseBody.path(AWSBedrockConstants.ASSESSMENTS);
        if (assessments.isArray() && !assessments.isEmpty()) {
            JsonNode firstAssessment = assessments.get(0);
            if (firstAssessment.isObject()) {
                ((ObjectNode) firstAssessment).remove("invocationMetrics");
            }
            return firstAssessment.toString();
        }
        return "";
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
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

    public boolean isPassthroughOnError() {

        return passthroughOnError;
    }

    public void setPassthroughOnError(boolean passthroughOnError) {

        this.passthroughOnError = passthroughOnError;
    }

    public boolean isShowAssessment() {

        return showAssessment;
    }

    public void setShowAssessment(boolean showAssessment) {

        this.showAssessment = showAssessment;
    }
}
