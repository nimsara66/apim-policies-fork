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

package org.wso2.apim.policies.mediation.ai.rag.injector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.jayway.jsonpath.JsonPath;
import org.apache.axis2.AxisFault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

import java.lang.reflect.Type;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PromptTemplate mediator.
 * <p>
 * <p>
 * The PromptTemplate mediator scans JSON payloads for template references in the format
 * {@code template://<template-name>?<param1>=<value1>&<param2>=<value2>} and replaces them
 * with predefined templates where parameter placeholders are substituted with provided values.
 * This is particularly useful for standardizing prompts across different API calls, especially
 * when working with large language models or AI services.
 * <p>
 * Template references in the payload are processed using regex pattern matching and URI parsing.
 * Each template placeholder in the format {@code [[parameter-name]]} is replaced with the
 * corresponding parameter value from the template URI query string.
 * <p>
 * Configuration is provided through a JSON array of template objects, each containing a name and
 * prompt definition:
 * <pre>
 * [
 *   {
 *     "name": "translate",
 *     "prompt": "Translate the following text from [[from]] to [[to]]: [[text]]"
 *   },
 *   {
 *     "name": "summarize",
 *     "prompt": "Summarize the following content in [[length]] words: [[content]]"
 *   }
 * ]
 * </pre>
 * <p>
 * Example usage in a payload:
 * <pre>
 * {
 *   "messages": [
 *     {
 *       "role": "user",
 *       "content": "template://translate?from=english&to=spanish&text=Hello world"
 *     }
 *   ]
 * }
 * </pre>
 * <p>
 * The mediator would transform this to:
 * <pre>
 * {
 *   "messages": [
 *     {
 *       "role": "user",
 *       "content": "Translate the following text from english to spanish: Hello world"
 *     }
 *   ]
 * }
 * </pre>
 */
public class RAGInjector extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(RAGInjector.class);

    private double threshold = 0.8;
    private int timeout = 3600;
    private String jsonPath = "";
    private String embeddingProviderType = "azure-openai";
    private String vectorDBProviderType = "zilliz";

    // Embedding provider security
    private String openaiApiKey;
    private String openaiEmbeddingEndpoint;
    private String openaiEmbeddingModel;
    private String mistralApiKey;
    private String mistralEmbeddingEndpoint;
    private String mistralEmbeddingModel;
    private String azureOpenaiApiKey;
    private String azureOpenaiEmbeddingEndpoint;
    private String injectorTemplateConfig;

    // VectorDB provider security
    private String zillizApiKey =
            "57ce1341ced8e7dd7f90b238bb85938ac560974755d9c2be6d38ae345e13450291854e4c6caf5ece1f9f58f031f1b55f04364fac";
    private String vectorSearchEndpoint =
            "https://in03-039eeda036f2801.serverless.gcp-us-west1.cloud.zilliz.com/v2/vectordb/entities/search";

    private final Map<String, String> injectorTemplates = new HashMap<>();
    private EmbeddingProvider embeddingProvider;
    private VectorDBProvider vectorDBProvider;

    /**
     * Initializes the RAGInjector mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing RAGInjector Mediator.");
        }
        this.embeddingProvider = createEmbeddingProvider();
        this.vectorDBProvider = createVectorDBProvider();
    }

    /**
     * Destroys the RAGInjector mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    /**
     * Mediates the message context by transforming the payload using prompt templates.
     * <p>
     * This method looks for placeholders in the JSON payload that match the predefined templates, and replaces
     * them with the appropriate values. It logs the mediation progress and handles any exceptions that occur during
     * the mediation process.
     *
     * @param messageContext The message context containing the JSON payload to be mediated.
     * @return {@code true} to continue the mediation process.
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Mediating message context with RAG.");
        }

        try {
            findAndTransformPayload(messageContext);
        } catch (Exception e) {
            logger.error("Error during mediation of message context", e);
        }

        return true;
    }

    /**
     * Finds and transforms the payload in the message context by resolving template placeholders.
     * <p>
     * This method searches the JSON content for template placeholders in the form of
     * {@code template://<template-name>?<params>} and replaces them with the corresponding template values.
     *
     * @param messageContext The message context containing the JSON payload.
     * @throws AxisFault If an error occurs while modifying the payload.
     */
    private void findAndTransformPayload(MessageContext messageContext) throws AxisFault {
        if (logger.isDebugEnabled()) {
            logger.debug("Injecting JSON payload with RAG.");
        }

        // Extract JSON content from the message context
        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return;
        }

        String content;
        if (this.jsonPath == null || this.jsonPath.isEmpty()) {
            content = jsonContent;
        } else {
            content = JsonPath.read(jsonContent, this.jsonPath).toString();
        }
        // Remove quotes at beginning and end
        String cleanedText = content.replaceAll(RAGInjectorConstants.TEXT_CLEAN_REGEX, "").trim();

        String updatedJsonContent = jsonContent;

        // Regex to find rag://<rag-injector-template-name>?<params>
        Pattern pattern = Pattern.compile(RAGInjectorConstants.RAG_INJECTOR_REGEX);
        Matcher matcher = pattern.matcher(jsonContent);

        while (matcher.find()) {
            // ex: rag://apim-docs-rag?collectionName=docs_apim_data&limit=10&outputFields=%5B%22%2A%22%5D
            String matched = matcher.group();

            try {
                // Parse the matched string as a URI
                URI uri = new URI(matched);
                String injectorName = uri.getHost(); // apim-docs-rag
                String template = injectorTemplates.get(injectorName);
                if (template == null) return;

                String query = uri.getQuery(); // collectionName=docs_apim_data&limit=10&outputFields=%5B%22%2A%22%5D
                // Parse query parameters
                Map<String, String> params = new HashMap<>();
                if (query != null) {
                    String[] pairs = query.split("&");
                    for (String pair : pairs) {
                        String[] keyValue = pair.split("=", 2);
                        if (keyValue.length == 2) {
                            String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                            String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                            params.put(key, value);
                        }
                    }
                }

                // Similarity is calculated on the cleaned content
                JsonNode embeddings = this.embeddingProvider.getEmbedding(cleanedText);
                String retrievedContext = this.vectorDBProvider.retrieve(embeddings, params, logger);

                // Replace placeholders in template
                String resolvedPrompt = template
                        .replaceAll(RAGInjectorConstants.RAG_INJECTOR_CONTEXT_REFERENCE, retrievedContext);
                ObjectMapper mapper = new ObjectMapper();
                String resolvedPromptEscaped = mapper.writeValueAsString(resolvedPrompt)
                        .replaceAll(RAGInjectorConstants.TEXT_CLEAN_REGEX, "").trim();


                // Directly replace in updatedJsonContent
                updatedJsonContent = updatedJsonContent.replace(matched, resolvedPromptEscaped);
            } catch (Exception e) {
                logger.error("Error while transforming template for match: " + matched, e);
            }
        }

        // Update the payload
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        JsonUtil.getNewJsonPayload(axis2MC, updatedJsonContent,
                true, true);
    }

    private EmbeddingProvider createEmbeddingProvider() {
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(this.timeout)
                .setConnectionRequestTimeout(this.timeout)
                .setSocketTimeout(this.timeout)
                .build();

        CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build();

        EmbeddingProviderType type = EmbeddingProviderType.fromString(this.embeddingProviderType);

        switch (type) {
            case MISTRAL:
                return new MistralEmbeddingProvider(
                        httpClient,
                        this.mistralApiKey,
                        this.mistralEmbeddingEndpoint,
                        this.mistralEmbeddingModel
                );

            case OPENAI:
                return new OpenAIEmbeddingProvider(
                        httpClient,
                        this.openaiApiKey,
                        this.openaiEmbeddingEndpoint,
                        this.openaiEmbeddingModel
                );

            case AZURE_OPENAI:
                /*
                return new AzureOpenAIEmbeddingProvider(
                        httpClient,
                        this.azureOpenaiApiKey,
                        this.azureOpenaiEmbeddingEndpoint
                );
                */

                return new AzureOpenAIEmbeddingProvider(
                        httpClient,
                        "EuwUKYGoCFI7B50vkcEWzUpJoM29eCQKENT6DIwaZnSfDlxv1R9RJQQJ99BDACHYHv6XJ3w3AAAAACOGocG9",
                        "https://bijiraairnd4138173133.openai.azure.com/openai/deployments/text-embedding-3-small/embeddings?api-version=2023-05-15"
                );

            default:
                throw new IllegalArgumentException("Unsupported provider: " + this.embeddingProviderType);
        }
    }

    private VectorDBProvider createVectorDBProvider() {
        VectorDBProviderType type = VectorDBProviderType.fromString(this.vectorDBProviderType);

        switch (type) {
            case ZILLIZ:
                RequestConfig requestConfig = RequestConfig.custom()
                        .setConnectTimeout(this.timeout)
                        .setConnectionRequestTimeout(this.timeout)
                        .setSocketTimeout(this.timeout)
                        .build();

                CloseableHttpClient httpClient = HttpClients.custom()
                        .setDefaultRequestConfig(requestConfig)
                        .build();

                return new ZillizVectorDBProvider(
                        httpClient,
                        zillizApiKey,
                        vectorSearchEndpoint
                );
            default:
                throw new IllegalArgumentException("Unsupported vector db: " + this.embeddingProviderType);
        }
    }

    /**
     * Extracts the JSON content from the provided message context.
     * <p>
     * This method retrieves the JSON payload from the message context and returns it as a string.
     *
     * @param messageContext The message context containing the JSON payload.
     * @return The extracted JSON content as a string, or {@code null} if no JSON content is found.
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    public String getInjectorTemplateConfig() {

        return injectorTemplateConfig;
    }

    public void setInjectorTemplateConfig(String injectorTemplateConfig) {

        this.injectorTemplateConfig = injectorTemplateConfig;

        try {
            Gson gson = new Gson();
            Type listType = new TypeToken<List<Map<String, String>>>() {}.getType();
            List<Map<String, String>> templates = gson.fromJson(injectorTemplateConfig, listType);

            for (Map<String, String> item : templates) {
                String name = item.get(RAGInjectorConstants.PROMPT_TEMPLATE_NAME);
                String prompt = item.get(RAGInjectorConstants.PROMPT_TEMPLATE_PROMPT);
                injectorTemplates.put(name, prompt);
            }
        } catch (Exception e) {
            logger.error("Invalid prompt template provided: " + injectorTemplateConfig, e);
        }
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }
}
