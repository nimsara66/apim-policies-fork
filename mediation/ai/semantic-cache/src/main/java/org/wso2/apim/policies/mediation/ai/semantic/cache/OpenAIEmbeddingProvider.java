package org.wso2.apim.policies.mediation.ai.semantic.cache;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class OpenAIEmbeddingProvider implements EmbeddingProvider {

    private final CloseableHttpClient httpClient;
    private final String openAiApiKey;
    private final String endpointUrl;
    private final String model;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public OpenAIEmbeddingProvider(CloseableHttpClient httpClient, String openAiApiKey, String endpointUrl, String model) {
        this.httpClient = httpClient;
        this.openAiApiKey = openAiApiKey;
        this.endpointUrl = endpointUrl;
        this.model = model;
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
