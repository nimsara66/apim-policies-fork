package org.wso2.apim.policies.mediation.ai.rag.injector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.logging.Log;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public class ZillizVectorDBProvider implements VectorDBProvider {

    private final CloseableHttpClient httpClient;
    private final String zillizApiKey;
    private final String vectorSearchUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ZillizVectorDBProvider(CloseableHttpClient httpClient, String zillizApiKey, String vectorSearchUrl) {
        this.httpClient = httpClient;
        this.zillizApiKey = zillizApiKey;
        this.vectorSearchUrl = vectorSearchUrl;
    }
    @Override
    public String retrieve(JsonNode embeddings, Map<String, String> options, Log logger) throws IOException {
        if (!checkRequiredfields(options)) return "";

        HttpPost post = new HttpPost(this.vectorSearchUrl);
        post.setHeader("Authorization", "Bearer " + this.zillizApiKey);
        post.setHeader("Content-Type", "application/json");

        // Build request JSON
        ObjectNode requestBody = this.objectMapper.createObjectNode();
        requestBody.put("collectionName", options.get("collectionName"));
        requestBody.set("data", embeddings);
        requestBody.put("limit", Integer.parseInt(options.get("limit")));
        if (options.get("outputFields") != null) {
            // Parse the string into a List
            ArrayNode outputFields = (ArrayNode) objectMapper.readTree(options.get("outputFields"));
            requestBody.set("outputFields", outputFields);
        }
        String json = objectMapper.writeValueAsString(requestBody);
        post.setEntity(new StringEntity(json, StandardCharsets.UTF_8));

        try (CloseableHttpResponse response = httpClient.execute(post)) {
            String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            JsonNode root = objectMapper.readTree(responseBody);
            JsonNode data = root.path("data");

            return data.toString();
        } catch (Exception e) {
            logger.error("Error while retrieving data from Zilliz: ", e);
        }
        return "";
    }

    private boolean checkRequiredfields(Map<String, String> options) {
        return options.get("collectionName") != null && options.get("limit") != null;
    }
}
