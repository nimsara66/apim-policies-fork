package org.wso2.apim.policies.mediation.ai.rag.injector;

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

public class MistralEmbeddingProvider implements EmbeddingProvider {

    private final CloseableHttpClient httpClient;
    private final String mistralApiKey;
    private final String endpointUrl;
    private final String model;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public MistralEmbeddingProvider(CloseableHttpClient httpClient, String mistralApiKey, String endpointUrl,
                                    String model) {
        this.httpClient = httpClient;
        this.mistralApiKey = mistralApiKey;
        this.endpointUrl = endpointUrl;
        this.model = model;
    }

    @Override
    public JsonNode getEmbedding(String input) throws IOException {
        HttpPost post = new HttpPost(endpointUrl);
        post.setHeader("Authorization", "Bearer " + mistralApiKey);
        post.setHeader("Content-Type", "application/json");

        // Build the JSON payload
        ObjectNode body = objectMapper.createObjectNode();
        body.put("model", model);
        body.put("input", input);
        String jsonBody = objectMapper.writeValueAsString(body);

        post.setEntity(new StringEntity(jsonBody, StandardCharsets.UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(post)) {
            String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            JsonNode root = objectMapper.readTree(json);

            return root.path("data").get(0).path("embedding");
        }
    }

    @Override
    public List<float[]> getEmbeddings(List<String> input) throws IOException {
        HttpPost post = new HttpPost(endpointUrl);
        post.setHeader("Authorization", "Bearer " + mistralApiKey);
        post.setHeader("Content-Type", "application/json");

        // Build the JSON payload
        ObjectNode body = objectMapper.createObjectNode();
        body.put("model", model);
        ArrayNode inputArray = objectMapper.valueToTree(input);
        body.set("input", inputArray);
        String jsonBody = objectMapper.writeValueAsString(body);

        post.setEntity(new StringEntity(jsonBody, StandardCharsets.UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(post)) {
            String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            JsonNode root = objectMapper.readTree(json);
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
