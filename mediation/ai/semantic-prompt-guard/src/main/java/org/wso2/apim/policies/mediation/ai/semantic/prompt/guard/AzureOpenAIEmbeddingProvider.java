package org.wso2.apim.policies.mediation.ai.semantic.prompt.guard;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class AzureOpenAIEmbeddingProvider implements EmbeddingProvider {

    private final CloseableHttpClient httpClient;
    private final String azureApiKey;
    // e.g., https://<your-resource-name>.openai.azure.com/openai/deployments/<deployment-id>/embeddings?api-version=2024-02-15-preview
    private final String endpointUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AzureOpenAIEmbeddingProvider(CloseableHttpClient httpClient, String azureApiKey, String endpointUrl) {
        this.httpClient = httpClient;
        this.azureApiKey = azureApiKey;
        this.endpointUrl = endpointUrl;
    }

    @Override
    public float[] getEmbedding(String input) throws IOException {
        HttpPost post = new HttpPost(endpointUrl);
        post.setHeader("api-key", azureApiKey);
        post.setHeader("Content-Type", "application/json");

        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("input", input);
        String json = objectMapper.writeValueAsString(requestBody);
        post.setEntity(new StringEntity(json, StandardCharsets.UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(post)) {
            String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            JsonNode root = objectMapper.readTree(responseBody);
            JsonNode embeddingArray = root.path("data").get(0).path("embedding");

            float[] embedding = new float[embeddingArray.size()];
            for (int i = 0; i < embedding.length; i++) {
                embedding[i] = (float) embeddingArray.get(i).asDouble();
            }
            return embedding;
        }
    }
}
