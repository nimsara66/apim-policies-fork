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
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.ejml.simple.SimpleMatrix;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.regex.PatternSyntaxException;

/**
 * Semantic Prompt Guard mediator.
 * <p>
 * A Synapse mediator that performs semantic validation of message payloads using vector similarity against
 * pre-configured "allow" and "deny" prompt rules. This guardrail is designed to provide intelligent content 
 * moderation using embedding-based similarity scores rather than static pattern matching.
 * <p>
 * The rules are configured as JSON containing lists of "allowPrompts" and/or "denyPrompts". Each prompt is
 * embedded using a pluggable {@link EmbeddingProvider}, and incoming payloads (optionally extracted via a JSONPath)
 * are compared against these embeddings to determine compliance.
 * <p>
 * Supported providers include OpenAI, Mistral, Azure OpenAI, and others registered via SPI. Threshold-based 
 * cosine similarity is used to evaluate rule matches. If a rule match is found, the mediator can:
 * <ul>
 *   <li>Allow or deny processing based on match type</li>
 *   <li>Build an assessment object summarizing the violation or decision</li>
 *   <li>Trigger a fault sequence with enriched error context</li>
 * </ul>
 * This is useful for applications such as prompt injection prevention, LLM content control, or semantic compliance checks.
 *
 * <p>
 * Configurable parameters include:
 * <ul>
 *   <li>{@code threshold} - Minimum similarity (in percentage) to consider a match</li>
 *   <li>{@code embeddingProviderType} - The type of embedding provider to use</li>
 *   <li>{@code jsonPath} - (Optional) JSON path to extract content from the payload</li>
 *   <li>{@code timeout}, {@code embeddingDimensions}, API keys, and endpoint URLs for supported providers</li>
 * </ul>
 *
 * When validation fails, this mediator halts further processing, triggers a fault sequence, and updates the
 * {@link org.apache.synapse.MessageContext} with detailed error metadata.
 *
 * Example use cases:
 * <ul>
 *   <li>Guarding AI model endpoints from malicious or out-of-scope prompts</li>
 *   <li>Enforcing semantic guardrails on incoming API payloads</li>
 *   <li>Allow/deny filtering based on semantic meaning rather than keywords</li>
 * </ul>
 *
 * @see EmbeddingProvider
 * @see SemanticPromptGuardConstants
 */
public class SemanticPromptGuard extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(SemanticPromptGuard.class);
    private static final APIManagerConfiguration apimConfig =
            ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService()
                    .getAPIManagerConfiguration();

    private String name;
    private String rules;
    private String jsonPath = "";
    private boolean hideAssessment = false;
    private double threshold = 90;

    private int embeddingDimension;
    private SimpleMatrix ruleEmbeddings;
    private List<SemanticPromptGuardConstants.PromptType> ruleTypes;
    private List<String> ruleContent;
    private EmbeddingProvider embeddingProvider;
    private SemanticPromptGuardConstants.RuleProcessingMode processingMode;

    /**
     * Initializes the SemanticPromptGuard mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        this.embeddingProvider = createEmbeddingProvider();
        try {
            this.embeddingDimension = this.embeddingProvider.getEmbeddingDimension();
        } catch (IOException e) {
            throw new RuntimeException("Unable to get embedding dimension for provider: " + this.embeddingProvider, e);
        }
        processRules(rules);

        if (logger.isDebugEnabled()) {
            logger.debug("Initializing SemanticPromptGuard.");
        }
    }

    private void processRules(String rules) {
        try {
            Gson gson = new Gson();
            Type mapType = new TypeToken<Map<String, List<String>>>() {}.getType();
            Map<String, List<String>> rulesMap = gson.fromJson(rules, mapType);

            List<String> allowPrompts = rulesMap.getOrDefault("allowPrompts", Collections.emptyList());
            List<String> denyPrompts = rulesMap.getOrDefault("denyPrompts", Collections.emptyList());

            int totalPrompts = allowPrompts.size() + denyPrompts.size();

            this.ruleEmbeddings = new SimpleMatrix(totalPrompts, this.embeddingDimension);
            this.ruleTypes = new ArrayList<>(totalPrompts);
            this.ruleContent = new ArrayList<>();

            int row = 0;

            // Batch embed deny prompts
            if (!denyPrompts.isEmpty()) {
                this.processingMode = SemanticPromptGuardConstants.RuleProcessingMode.DENY_ONLY;
                for (String denyPrompt : denyPrompts) {
                    float[] denyPromptEmbedding = this.embeddingProvider.getEmbedding(denyPrompt);
                    storePrompt(row, denyPromptEmbedding, SemanticPromptGuardConstants.PromptType.DENY, denyPrompt);
                    row++;
                }
            }

            // Batch embed allow prompts
            if (!allowPrompts.isEmpty()) {
                if (this.processingMode == null) {
                    this.processingMode = SemanticPromptGuardConstants.RuleProcessingMode.ALLOW_ONLY;
                } else {
                    this.processingMode = SemanticPromptGuardConstants.RuleProcessingMode.HYBRID;
                }

                for (String allowPrompt : allowPrompts) {
                    float[] allowPromptEmbedding = this.embeddingProvider.getEmbedding(allowPrompt);
                    storePrompt(row, allowPromptEmbedding, SemanticPromptGuardConstants.PromptType.ALLOW, allowPrompt);
                    row++;
                }
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Rules added successfully: " + rules);
            }

        } catch (PatternSyntaxException | IOException e) {
            throw new RuntimeException("Invalid rules: " + rules, e);
        }
    }

    private EmbeddingProvider createEmbeddingProvider() {
        Map<String, Map<String, String>> providers = apimConfig.getEmbeddingProviders();

        if (providers.isEmpty()) {
            throw new IllegalArgumentException("No embedding providers configured in API Manager.");
        }

        Map.Entry<String, Map<String, String>> providerEntry =
                apimConfig.getEmbeddingProviders().entrySet().iterator().next();
        Map<String, String> providerConfig = providerEntry.getValue();

        // Load via ServiceLoader
        ServiceLoader<EmbeddingProvider> loader = ServiceLoader.load(EmbeddingProvider.class);
        for (EmbeddingProvider provider : loader) {
            if (provider.getType().equalsIgnoreCase(providerEntry.getKey())) {
                provider.init(providerConfig);
                return provider;
            }
        }

        throw new IllegalArgumentException("Unsupported or unregistered provider: " + providerEntry.getKey());
    }

    /**
     * Destroys the SemanticPromptGuard mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
        System.out.println("Destroyed.");
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Beginning payload validation.");
        }

        try {
            boolean validationResult = applyRules(messageContext);

            if (!validationResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        SemanticPromptGuardConstants.GUARDRAIL_APIM_EXCEPTION_CODE);
                messageContext.setProperty(SemanticPromptGuardConstants.ERROR_TYPE,
                        SemanticPromptGuardConstants.SEMANTIC_PROMPT_GUARD);
                messageContext.setProperty(SemanticPromptGuardConstants.CUSTOM_HTTP_SC,
                        SemanticPromptGuardConstants.GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject(messageContext);
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("Validation failed - triggering fault sequence.");
                }

                Mediator faultMediator = messageContext.getSequence(SemanticPromptGuardConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Exception occurred during mediation.", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    SemanticPromptGuardConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Error occurred during SemanticPromptGuard mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);
            return false;
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
    private boolean applyRules(MessageContext messageContext) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Applying rules.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return true;
        }

        // If no JSON path is specified, apply piiEntities to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return isAllowed(jsonContent, messageContext);

        }

        String content = JsonPath.read(jsonContent, this.jsonPath).toString();

        // Remove quotes at beginning and end
        String cleanedText = content.replaceAll(SemanticPromptGuardConstants.JSON_CLEAN_REGEX, "").trim();

        // Check if any extracted value by json path matches the piiEntities pattern
        return isAllowed(cleanedText, messageContext);
    }

    private boolean isAllowed(String jsonContent, MessageContext messageContext) throws IOException {

        if (jsonContent != null && !jsonContent.isEmpty()) {
            float[] similarityScores = calculateSimilarity(jsonContent);

            // Convert similarity scores to boolean matches
            List<Boolean> matches = new ArrayList<>(similarityScores.length);
            for (float score : similarityScores) {
                matches.add(score*100 >= this.threshold);
            }

            for (int i = 0; i < similarityScores.length; i++) {
                SemanticPromptGuardConstants.PromptType type = ruleTypes.get(i);

                if (matches.get(i)) {
                    if (type == SemanticPromptGuardConstants.PromptType.DENY) {
                        messageContext.setProperty(SemanticPromptGuardConstants.DENIED_PROMPT_KEY, ruleContent.get(i));
                        return false;
                    } else if (type == SemanticPromptGuardConstants.PromptType.ALLOW) {
                        return true;
                    }
                }
            }
        }

        return this.processingMode == SemanticPromptGuardConstants.RuleProcessingMode.DENY_ONLY;
    }

    private float[] calculateSimilarity(String prompt) throws IOException {
        float[] vector = this.embeddingProvider.getEmbedding(prompt);

        // Step 1: Convert the input vector to a SimpleMatrix
        SimpleMatrix query = new SimpleMatrix(1, vector.length);
        for (int i = 0; i < vector.length; i++) {
            query.set(0, i, vector[i]);
        }

        // Step 2: Calculate the dot products (s = V * q)“
        SimpleMatrix s = ruleEmbeddings.mult(query.transpose());

        // Step 3: Compute the norm of the query vector
        double nq = query.normF();

        // Step 4: Compute the norms of each row in ruleEmbeddings
        SimpleMatrix norms = new SimpleMatrix(ruleEmbeddings.getNumRows(), 1);
        for (int i = 0; i < ruleEmbeddings.getNumRows(); i++) {
            norms.set(i, 0, ruleEmbeddings.extractVector(true, i).normF());
        }

        // Step 5: Normalize the dot products by dividing by the product of norms (query_norm * row_norms)
        SimpleMatrix cosSim = s.divide(nq).elementDiv(norms);

        // Convert the result back to an array of floats
        float[] similarityScores = new float[cosSim.getNumRows()];
        for (int i = 0; i < cosSim.getNumRows(); i++) {
            similarityScores[i] = (float) cosSim.get(i, 0);
        }

        return similarityScores;
    }

    private String buildAssessmentObject(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Building guardrail assessment object.");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(SemanticPromptGuardConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(SemanticPromptGuardConstants.INTERVENING_GUARDRAIL, this.getName());
        assessmentObject.put(SemanticPromptGuardConstants.DIRECTION,
                messageContext.isResponse()? "RESPONSE" : "REQUEST");
        assessmentObject.put(SemanticPromptGuardConstants.ASSESSMENT_REASON, "Violation of guard prompts detected.");

        if (!this.hideAssessment) {
            JSONObject assessmentDetails = new JSONObject();
            if (this.processingMode == SemanticPromptGuardConstants.RuleProcessingMode.DENY_ONLY) {
                assessmentDetails.put("message", "One or more semantic rules are violated.");
                assessmentDetails.put("deniedRule",
                        messageContext.getProperty(SemanticPromptGuardConstants.DENIED_PROMPT_KEY));
            } else {
                assessmentDetails.put("message", "None of the allowed prompts are met.");

                JSONArray allowedRulesArray = new JSONArray();
                for (int i = 0; i < ruleTypes.size(); i++) {
                    if (SemanticPromptGuardConstants.PromptType.ALLOW.equals(ruleTypes.get(i))) {
                        allowedRulesArray.put(ruleContent.get(i));
                    }
                }
                assessmentDetails.put("allowedRules", allowedRulesArray);
            }

            assessmentObject.put(SemanticPromptGuardConstants.ASSESSMENTS, assessmentDetails);
        }
        return assessmentObject.toString();
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

    // Helper method to store the prompt and its data
    private void storePrompt(int row, float[] embedding, SemanticPromptGuardConstants.PromptType type, String prompt) {
        if (logger.isDebugEnabled()) {
            logger.debug("Storing embedding: " + Arrays.toString(embedding) +
                    " | Prompt: \"" + prompt + "\"");
        }

        for (int col = 0; col < this.embeddingDimension; col++) {
            ruleEmbeddings.set(row, col, embedding[col]);
        }
        ruleTypes.add(type);
        ruleContent.add(prompt);
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

    public void setRules(String rules) throws IOException {

        this.rules = rules;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public boolean isHideAssessment() {

        return hideAssessment;
    }

    public void setHideAssessment(boolean hideAssessment) {

        this.hideAssessment = hideAssessment;
    }

    public double getThreshold() {

        return threshold;
    }

    public void setThreshold(double threshold) {

        this.threshold = threshold;
    }
}
