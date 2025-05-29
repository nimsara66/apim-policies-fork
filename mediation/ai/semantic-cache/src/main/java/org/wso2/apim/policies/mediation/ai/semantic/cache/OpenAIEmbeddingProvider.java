package org.wso2.apim.policies.mediation.ai.semantic.cache;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OpenAIEmbeddingProvider implements EmbeddingProvider {

    private CloseableHttpClient httpClient;
    private String openAiApiKey;
    private String endpointUrl;
    private String model;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void init(Map<String, String> providerConfig) {

        this.openAiApiKey = providerConfig.get("apikey");
        this.endpointUrl = providerConfig.get("embedding_endpoint");
        this.model = providerConfig.get("embedding_model");

        if (openAiApiKey == null || endpointUrl == null || model == null) {
            throw new IllegalArgumentException("Missing required OpenAI configuration: 'apikey', 'embedding_endpoint', or 'embedding_model'");
        }

        int timeout = Integer.parseInt(providerConfig.getOrDefault("timeout",
                String.valueOf(SemanticCacheConstants.DEFAULT_TIMEOUT)));
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(timeout)
                .setConnectionRequestTimeout(timeout)
                .setSocketTimeout(timeout)
                .build();

        this.httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    @Override
    public String getType() {
        return "OPENAI";
    }

    @Override
    public float[] getEmbedding(String input) throws IOException {
        HttpPost post = new HttpPost(endpointUrl);
        post.setHeader("Authorization", "Bearer " + openAiApiKey);
        post.setHeader("Content-Type", "application/json");

        // Build request JSON
        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("model", model);
        requestBody.put("input", input);
        String json = objectMapper.writeValueAsString(requestBody);
        post.setEntity(new StringEntity(json, StandardCharsets.UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(post)) {
            String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            JsonNode root = objectMapper.readTree(responseBody);
            JsonNode embeddingArray = root.path("data").get(0).path("embedding");

            float[] embedding = new float[embeddingArray.size()];
            for (int i = 0; i < embedding.length; i++) {
                embedding[i] = (float) embeddingArray.get(i).asDouble();  // cast to float32
            }
            return embedding;
        }
    }

    @Override
    public List<float[]> getEmbeddings(List<String> input) throws IOException {
        HttpPost post = new HttpPost(endpointUrl);
        post.setHeader("Authorization", "Bearer " + openAiApiKey);
        post.setHeader("Content-Type", "application/json");

        // Build request JSON for batch
        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("model", model);
        ArrayNode inputArray = objectMapper.valueToTree(input);
        requestBody.set("input", inputArray);

        String json = objectMapper.writeValueAsString(requestBody);
        post.setEntity(new StringEntity(json, StandardCharsets.UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(post)) {
            String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            JsonNode root = objectMapper.readTree(responseBody);
            JsonNode dataArray = root.path("data");

            List<float[]> embeddings = new ArrayList<>(dataArray.size());
            for (JsonNode dataNode : dataArray) {
                JsonNode embeddingArray = dataNode.path("embedding");
                float[] embedding = new float[embeddingArray.size()];
                for (int i = 0; i < embedding.length; i++) {
                    embedding[i] = (float) embeddingArray.get(i).asDouble();
                }
                embeddings.add(embedding);
            }

            return embeddings;
        }
    }
}
