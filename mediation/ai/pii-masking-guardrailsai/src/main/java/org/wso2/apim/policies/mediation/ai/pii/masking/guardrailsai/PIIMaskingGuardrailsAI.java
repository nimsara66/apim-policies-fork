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

package org.wso2.apim.policies.mediation.ai.pii.masking.guardrailsai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import org.apache.axis2.AxisFault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.PatternSyntaxException;

/**
 * PII Masking/Redaction Mediator.
 * <p>
 * A Synapse custom mediator that detects and processes Personally Identifiable Information (PII) in
 * JSON payloads using regex patterns. This mediator can either mask PII by replacing detected values
 * with placeholders (e.g., &lt;Email_1&gt;) or redact them by replacing matches with fixed strings (e.g., *****).
 * <p>
 * Configuration is provided through:
 * <ul>
 *   <li>{@code piiEntities} – A JSON array of objects, each containing a {@code piiEntity} key and its corresponding {@code piiRegex} pattern.</li>
 *   <li>{@code jsonPath} – An optional JSONPath expression to extract a specific part of the payload before applying the masking/redaction logic.</li>
 *   <li>{@code redact} – A boolean flag indicating whether to redact (true) or mask (false) the PII.</li>
 * </ul>
 * <p>
 * The mediator maintains consistency between request and response flows by tracking masked values using a context property
 * ("PII_ENTITIES") so they can be reversed on the response if needed.
 * <p>
 * Example usage scenarios:
 * <ul>
 *   <li>Masking email addresses and names in API requests before logging or auditing.</li>
 *   <li>Redacting sensitive information before passing it to external systems.</li>
 * </ul>
 */
public class PIIMaskingGuardrailsAI extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(PIIMaskingGuardrailsAI.class);

    private String name;
    private String piiEntities;
    private String jsonPath = "";
    private boolean redact = false;
    private List<String> piiEntitiyList = new ArrayList<>();

    /**
     * Initializes the PIIMaskingRegex mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing PIIMaskingRegex.");
        }
    }

    /**
     * Destroys the PIIMaskingRegex mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Beginning payload validation.");
        }

        try {
            identifyPIIAndTransform(messageContext);
        } catch (Exception e) {
            logger.error("Exception occurred during mediation.", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    PIIMaskingGuardrailsAIConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Error occurred during PIIMaskingRegex mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);

            return false; // Stop further mediation
        }

        return true;
    }

    /**
     * Validates the payload of the message against the configured piiEntities pattern.
     * If a JSON path is specified, validation is performed only on the extracted value,
     * otherwise the entire payload is validated.
     *
     * @param messageContext The message context containing the payload to validate
     * @return {@code true} if the payload matches the pattern, {@code false} otherwise
     */
    private void identifyPIIAndTransform(MessageContext messageContext) throws AxisFault {
        if (logger.isDebugEnabled()) {
            logger.debug("Identifying PII.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return;
        }

        // If no JSON path is specified, apply piiEntities to the entire JSON content
        String updatedContent = "";
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            updatedContent = maskPIIFromContent(messageContext, jsonContent, redact);

        } else {
            String content = JsonPath.read(jsonContent, this.jsonPath).toString();

            // Remove quotes at beginning and end
            String cleanedText = content.replaceAll(PIIMaskingGuardrailsAIConstants.TEXT_CLEAN_REGEX, "").trim();

            // Check if any extracted value by json path matches the piiEntities pattern
            updatedContent =  maskPIIFromContent(messageContext, cleanedText, redact);
        }

        if (!updatedContent.isEmpty()) {
            if (this.jsonPath != null && !this.jsonPath.trim().isEmpty()) {
                DocumentContext ctx = JsonPath.parse(jsonContent);
                ctx.set(this.jsonPath, updatedContent);
                updatedContent = ctx.jsonString();
            }

            org.apache.axis2.context.MessageContext axis2MC =
                    ((Axis2MessageContext) messageContext).getAxis2MessageContext();
            JsonUtil.getNewJsonPayload(axis2MC, updatedContent,
                    true, true);
        }
    }

    private String maskPIIFromContent(MessageContext messageContext, String jsonContent, boolean redact) {

        if (jsonContent == null || jsonContent.isEmpty()) {
            return "";
        }

        boolean foundAndMasked = false;
        String maskedContent = jsonContent;


        if (!messageContext.isResponse()) {
            try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
                HttpPost post = new HttpPost("http://localhost:8000/validate");
                post.setHeader("Content-Type", "application/json");

                // Construct request payload
                ObjectMapper objectMapper = new ObjectMapper();
                ObjectNode requestBody = objectMapper.createObjectNode();
                requestBody.put("text", jsonContent);
                requestBody.put("redact", redact);

                // You can customize the list of PII entities as needed
                requestBody.set("piiEntities", objectMapper.valueToTree(piiEntitiyList));

                StringEntity entity = new StringEntity(requestBody.toString(), ContentType.APPLICATION_JSON);
                post.setEntity(entity);

                try (CloseableHttpResponse response = httpClient.execute(post)) {
                    int statusCode = response.getStatusLine().getStatusCode();
                    String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                    if (statusCode == 200) {
                        JsonNode root = objectMapper.readTree(responseBody);
                        JsonNode anonymizedTextNode = root.path("anonymizedText");
                        JsonNode assessment = root.path("assessment");
                        if (!anonymizedTextNode.isMissingNode()) {
                            if (assessment.isArray()) {
                                Map<String, String> maskedPIIEntities = new HashMap<>();
                                for (JsonNode item : assessment) {
                                    String piiEntity = item.path("piiEntity").asText();
                                    String piiValue = item.path("piiValue").asText();
                                    maskedPIIEntities.put(piiEntity, piiValue);
                                }
                                messageContext.setProperty("PII_ENTITIES", maskedPIIEntities);
                            }
                            return anonymizedTextNode.asText();
                        }
                    } else {
                        throw new IOException("Unexpected status code " + statusCode + ": " + responseBody);
                    }
                }
            } catch (IOException e) {
                logger.error("Failed to call PII masking service", e);
            }
        } else {
            Map<String, String> maskedPIIEntities = (Map<String, String>) messageContext.getProperty("PII_ENTITIES");

            if (maskedPIIEntities != null) {
                for (Map.Entry<String, String> entry : maskedPIIEntities.entrySet()) {
                    String original = entry.getKey();
                    String placeholder = entry.getValue();
                    maskedContent = maskedContent.replace(placeholder, original);
                    foundAndMasked = true;
                }
            }
        }

        if (foundAndMasked && logger.isDebugEnabled()) {
            logger.debug("Masked content: " + maskedContent);
        }

        return foundAndMasked? maskedContent: "";
    }

    private static String generateHexId(AtomicInteger counter) {
        int count = counter.getAndIncrement();
        return String.format("%04x", count); // 4-digit hex string, zero-padded
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

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getPiiEntities() {

        return piiEntities;
    }

    public void setPiiEntities(String piiEntities) {

        this.piiEntities = piiEntities;

        try {
            Gson gson = new Gson();
            Type listType = new TypeToken<List<String>>() {}.getType();
            this.piiEntitiyList = gson.fromJson(piiEntities, listType);
        } catch (PatternSyntaxException e) {
            logger.error("Invalid piiEntities pattern: " + piiEntities, e);
        }
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public boolean isRedact() {

        return redact;
    }

    public void setRedact(boolean redact) {

        this.redact = redact;
    }
}
