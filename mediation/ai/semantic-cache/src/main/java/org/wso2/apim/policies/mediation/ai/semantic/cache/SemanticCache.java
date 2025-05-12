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

package org.wso2.apim.policies.mediation.ai.semantic.cache;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.jayway.jsonpath.JsonPath;
import org.apache.axis2.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.synapse.mediators.builtin.RespondMediator;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.ejml.simple.SimpleMatrix;
import org.json.JSONObject;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;
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
public class SemanticCache extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(SemanticCache.class);

    private String name;
    private double threshold = 0.8;
    private int embeddingDimensions = 1024;
    private String jsonPath = "";
    private SimpleMatrix ruleEmbeddings;
    private List<String> ruleContents;

    /**
     * Initializes the SemanticCache mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("SemanticCache: Initialized.");
        }
    }

    /**
     * Destroys the SemanticCache mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
        System.out.println("SemanticCache: Destroyed.");
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("SemanticCache: Beginning payload validation.");
        }

        try {
            boolean isCacheHit = checkForCacheHit(messageContext);

            if (isCacheHit) {
                if (logger.isDebugEnabled()) {
                    logger.debug("SemanticCache: Cache hit! Returning cached JSON response.");
                }

                // Hardcoded JSON response
                String cachedJsonResponse = "{ \"message\": \"Hello from cache!\" }";

                // Set JSON payload
                org.apache.axis2.context.MessageContext axis2MC =
                        ((Axis2MessageContext) messageContext).getAxis2MessageContext();
                JsonUtil.getNewJsonPayload(axis2MC, cachedJsonResponse, true, true);

                // Set HTTP status and transport headers
                axis2MC.setProperty("HTTP_SC", 200); // HTTP 200 OK
                axis2MC.setProperty("X-Cache", "HIT");

                // Mark as JSON response properly
                axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/json");
                axis2MC.setProperty(Constants.Configuration.CONTENT_TYPE, "application/json");
                axis2MC.setDoingREST(true);

                // Clean up properties that could interfere
                axis2MC.removeProperty(PassThroughConstants.NO_ENTITY_BODY);

                // Set Synapse response flags
                messageContext.setProperty("RESPONSE", "true");
                messageContext.setTo(null);
                messageContext.setResponse(true);

                Axis2Sender.sendBack(messageContext);

                return false;
            }
        } catch (Exception e) {
            logger.error("SemanticCache: Exception occurred during mediation.", e);
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
    private boolean checkForCacheHit(MessageContext messageContext) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("SemanticCache: Identifying PII.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return true;
        }

        // If no JSON path is specified, apply piiEntities to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return checkForCacheHit(jsonContent);

        }

        String content = JsonPath.read(jsonContent, this.jsonPath).toString();

        // Remove quotes at beginning and end
        String cleanedText = content.replaceAll("^\"|\"$", "").trim();

        // Check if any extracted value by json path matches the piiEntities pattern
        return checkForCacheHit(cleanedText);
    }

    private boolean checkForCacheHit(String jsonContent) throws IOException {

        if (jsonContent != null && !jsonContent.isEmpty()) {

        }

        return true;
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

    // Helper to generate a random embedding vector (float32 values)
    private float[] generateRandomEmbedding() {
        Random random = new Random();
        float[] embedding = new float[this.embeddingDimensions];
        for (int i = 0; i < this.embeddingDimensions; i++) {
            embedding[i] = random.nextFloat(); // Or use fixed value if preferred
        }
        return embedding;
    }

    public double getThreshold() {

        return threshold;
    }

    public void setThreshold(double threshold) {

        this.threshold = threshold;
    }

    public int getEmbeddingDimensions() {

        return embeddingDimensions;
    }

    public void setEmbeddingDimensions(int embeddingDimensions) {

        this.embeddingDimensions = embeddingDimensions;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }
}
