package org.wso2.apim.policies.mediation.ai.semantic.prompt.guard;

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

public class MistralEmbeddingProvider implements EmbeddingProvider {

    private CloseableHttpClient httpClient;
    private String mistralApiKey;
    private String endpointUrl;
    private String model;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void init(Map<String, String> providerConfig) {

        this.mistralApiKey = providerConfig.get("apikey");
        this.endpointUrl = providerConfig.get("embedding_endpoint");
        this.model = providerConfig.get("embedding_model");

        if (mistralApiKey == null || endpointUrl == null || model == null) {
            throw new IllegalArgumentException(
                    "Missing required Mistral configuration: 'apikey', 'embedding_endpoint', or 'embedding_model'");
        }

        int timeout = Integer.parseInt(providerConfig.getOrDefault("timeout",
                String.valueOf(SemanticPromptGuardConstants.DEFAULT_TIMEOUT)));
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
        return "MISTRAL";
    }

    @Override
    public int getEmbeddingDimension() throws IOException {

        return getEmbedding(this.getType()).length;
    }

    @Override
    public float[] getEmbedding(String input) throws IOException {
        for (int attempt = 1; attempt <= SemanticPromptGuardConstants.MAX_RETRY; attempt++) {
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
                int statusCode = response.getStatusLine().getStatusCode();
                String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

                if (statusCode >= 200 && statusCode < 300) {
                    JsonNode root = objectMapper.readTree(json);
                    JsonNode embeddingArray = root.path("data").get(0).path("embedding");

                    float[] embedding = new float[embeddingArray.size()];
                    for (int i = 0; i < embedding.length; i++) {
                        embedding[i] = (float) embeddingArray.get(i).asDouble();
                    }
                    return embedding;
                } else {
                    throw new IOException("Unexpected status code " + statusCode + ": " + json);
                }
            } catch (IOException e) {
                if (attempt == SemanticPromptGuardConstants.MAX_RETRY) {
                    throw e;
                }
                try {
                    long backoff = (long) Math.pow(2, attempt) * 1000L; // 2s, 4s, 8s
                    Thread.sleep(backoff);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted during backoff", ie);
                }
            }
        }

        throw new IOException("Failed to get embedding after " + SemanticPromptGuardConstants.MAX_RETRY + " attempts");
    }

}
