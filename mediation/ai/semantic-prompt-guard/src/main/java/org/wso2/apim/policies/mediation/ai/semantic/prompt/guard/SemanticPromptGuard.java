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

package org.wso2.apim.policies.mediation.ai.semantic.prompt.guard;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.jayway.jsonpath.JsonPath;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import redis.clients.jedis.UnifiedJedis;
import redis.clients.jedis.search.FTCreateParams;
import redis.clients.jedis.search.IndexDataType;
import redis.clients.jedis.search.schemafields.SchemaField;
import redis.clients.jedis.search.schemafields.TagField;
import redis.clients.jedis.search.schemafields.TextField;
import redis.clients.jedis.search.schemafields.VectorField;

import java.lang.reflect.Type;
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
public class SemanticPromptGuard extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(SemanticPromptGuard.class);

    private String name;
    private String rules;
    private String jsonPath = "";

    /**
     * Initializes the SemanticPromptGuard mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("SemanticPromptGuard: Initialized.");
        }
    }

    /**
     * Destroys the SemanticPromptGuard mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
        System.out.println("SemanticPromptGuard: Destroyed.");
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("SemanticPromptGuard: Beginning payload validation.");
        }

        try {
            return applyRules(messageContext);
        } catch (Exception e) {
            logger.error("SemanticPromptGuard: Exception occurred during mediation.", e);
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
    private boolean applyRules(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("SemanticPromptGuard: Identifying PII.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return true;
        }

        // If no JSON path is specified, apply piiEntities to the entire JSON content
        String updatedContent = "";
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return validate(jsonContent);

        }

        String content = JsonPath.read(jsonContent, this.jsonPath).toString();

        // Remove quotes at beginning and end
        String cleanedText = content.replaceAll("^\"|\"$", "").trim();

        // Check if any extracted value by json path matches the piiEntities pattern
        return validate(cleanedText);
    }

    private boolean validate(String jsonContent) {

        if (jsonContent == null || jsonContent.isEmpty()) {
            return true;
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

    public String getRules() {

        return rules;
    }

    public void setRules(String rules) {

        this.rules = rules;

        try {
            Gson gson = new Gson();
            Type mapType = new TypeToken<Map<String, List<String>>>() {}.getType();
            Map<String, List<String>> rulesMap = gson.fromJson(rules, mapType);

            List<String> allowPrompts = rulesMap.getOrDefault("allowPrompts", Collections.emptyList());
            List<String> denyPrompts = rulesMap.getOrDefault("denyPrompts", Collections.emptyList());

            UnifiedJedis jedis = new UnifiedJedis("redis://localhost:6379");

            // Create index if not exists
            try {
                jedis.ftInfo("vector_idx");
            } catch (Exception e) {
                SchemaField[] schema = {
                        TextField.of("content"),
                        TagField.of("type"),
                        VectorField.builder()
                                .fieldName("embedding")
                                .algorithm(VectorField.VectorAlgorithm.HNSW)
                                .attributes(
                                        Map.of(
                                                "TYPE", "FLOAT32",
                                                "DIM", 768,
                                                "DISTANCE_METRIC", "L2"
                                        )
                                )
                                .build()
                };

                jedis.ftCreate("vector_idx",
                        FTCreateParams.createParams()
                                .addPrefix("doc:")
                                .on(IndexDataType.HASH),
                        schema
                );
            }

            // Static dummy embedding (replace with real one if needed)
            byte[] staticEmbedding = new byte[768 * 4]; // float32 (4 bytes) * 768
            new Random().nextBytes(staticEmbedding);   // or use fixed values if preferred

            int docIndex = 0;

            // Store allow prompts
            for (String prompt : allowPrompts) {
                String redisKey = "doc:" + docIndex++;
                jedis.hset(redisKey, Map.of("content", prompt, "type", "allow"));
                jedis.hset(redisKey.getBytes(), "embedding".getBytes(), staticEmbedding);
            }

            // Store deny prompts
            for (String prompt : denyPrompts) {
                String redisKey = "doc:" + docIndex++;
                jedis.hset(redisKey, Map.of("content", prompt, "type", "deny"));
                jedis.hset(redisKey.getBytes(), "embedding".getBytes(), staticEmbedding);
            }

            if (logger.isDebugEnabled()) {
                logger.debug("SemanticPromptGuard: Rules added successfully: " + rules);
            }
        } catch (PatternSyntaxException e) {
            logger.error("SemanticPromptGuard: Invalid rules: " + rules, e);
        }
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }
}
