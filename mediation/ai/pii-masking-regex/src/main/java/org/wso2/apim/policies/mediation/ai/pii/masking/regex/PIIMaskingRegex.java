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

package org.wso2.apim.policies.mediation.ai.pii.masking.regex;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import org.apache.axis2.AxisFault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

import java.lang.reflect.Type;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Regex Guardrail mediator.
 * <p>
 * A mediator that performs piiEntities-based validation on payloads according to specified patterns.
 * This guardrail can be configured with JSON path expressions to target specific parts of JSON payloads
 * and apply piiEntities pattern validation against them. The validation result can be inverted if needed.
 * <p>
 * When validation fails, the mediator triggers a fault sequence and enriches the message context
 * with appropriate error details.
 */
public class PIIMaskingRegex extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(PIIMaskingRegex.class);

    private String name;
    private String piiEntities;
    private String jsonPath = "";
    private boolean redact = false;
    private final Map<String, Pattern> patterns = new HashMap<>();

    /**
     * Initializes the PIIMaskingRegex mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("PIIMaskingRegex: Initialized.");
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
            logger.debug("PIIMaskingRegex: Beginning payload validation.");
        }

        try {
            // Do nothing for response flow - redact
            if (!messageContext.isResponse() || !this.redact) identifyPIIAndTransform(messageContext);
        } catch (Exception e) {
            logger.error("PIIMaskingRegex: Exception occurred during mediation.", e);
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
            logger.debug("PIIMaskingRegex: Identifying PII.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return;
        }

        // If no JSON path is specified, apply piiEntities to the entire JSON content
        String updatedContent = "";
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            updatedContent = redact ? redactPIIFromContent(jsonContent)
                    : maskPIIFromContent(messageContext, jsonContent);

        } else {
            String content = JsonPath.read(jsonContent, this.jsonPath).toString();

            // Remove quotes at beginning and end
            String cleanedText = content.replaceAll("^\"|\"$", "").trim();

            // Check if any extracted value by json path matches the piiEntities pattern
            updatedContent =  redact ? redactPIIFromContent(cleanedText)
                    : maskPIIFromContent(messageContext, cleanedText);
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

    private String maskPIIFromContent(MessageContext messageContext, String jsonContent) {

        if (jsonContent == null || jsonContent.isEmpty()) {
            return "";
        }

        boolean foundAndMasked = false;
        String maskedContent = jsonContent;

        if (!messageContext.isResponse()) {
            Map<String, String> maskedPIIEntities = new LinkedHashMap<>();

            for (Map.Entry<String, Pattern> entry : patterns.entrySet()) {
                String key = entry.getKey();
                Pattern pattern = entry.getValue();
                Matcher matcher = pattern.matcher(maskedContent);

                StringBuilder resultBuffer = new StringBuilder();
                // If pattern matches, replace all occurrences
                while (matcher.find()) {
                    String original = matcher.group();

                    // Reuse if already seen
                    String masked = maskedPIIEntities.get(original);
                    if (masked == null) {
                        // Generate unique placeholder like <Person1>, <Email1>
                        int count = Collections.frequency(maskedPIIEntities.values(), key);
                        masked = "<" + key + "_" + (count + 1) + ">";
                        maskedPIIEntities.put(original, masked);
                    }
                    matcher.appendReplacement(resultBuffer, Matcher.quoteReplacement(masked));
                    foundAndMasked = true;
                }
                matcher.appendTail(resultBuffer);
                maskedContent = resultBuffer.toString();
            }
            // Store PII_ENTITIES for later reversal
            if (!maskedPIIEntities.isEmpty()) {
                messageContext.setProperty("PII_ENTITIES", maskedPIIEntities);
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

        if (foundAndMasked) {
            // Log or update masked content here if needed
            if (logger.isDebugEnabled()) {
                logger.debug("Masked content: " + maskedContent);
            }
        }

        return foundAndMasked? maskedContent: "";
    }

    private String redactPIIFromContent(String jsonContent) {
        if (jsonContent == null || jsonContent.isEmpty()) {
            return "";
        }

        boolean foundAndMasked = false;
        String maskedContent = jsonContent;

        for (Map.Entry<String, Pattern> entry : patterns.entrySet()) {
            Pattern pattern = entry.getValue();
            Matcher matcher = pattern.matcher(maskedContent);

            // If pattern matches, replace all occurrences
            if (matcher.find()) {
                foundAndMasked = true;
                maskedContent = matcher.replaceAll("*****");
            }
        }

        if (foundAndMasked) {
            // Log or update masked content here if needed
            if (logger.isDebugEnabled()) {
                logger.debug("Masked content: " + maskedContent);
            }
        }

        return foundAndMasked? maskedContent: "";
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
            Type listType = new TypeToken<List<Map<String, String>>>() {}.getType();
            List<Map<String, String>> templates = gson.fromJson(piiEntities, listType);

            for (Map<String, String> item : templates) {
                String piiEntity = item.get(PIIMaskingRegexConstants.PII_ENTITY);
                String piiRegex = item.get(PIIMaskingRegexConstants.PII_REGEX);
                patterns.put(piiEntity, Pattern.compile(piiRegex));
            }
            if (logger.isDebugEnabled()) {
                logger.debug("PIIMaskingRegex: Regex pattern compiled successfully: " + piiEntities);
            }
        } catch (PatternSyntaxException e) {
            logger.error("PIIMaskingRegex: Invalid piiEntities pattern: " + piiEntities, e);
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
