package org.wso2.apim.policies.mediation.ai.semantic.cache;

import org.apache.http.impl.client.CloseableHttpClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public interface EmbeddingProvider {
    /**
     * Initialize the provider with required HTTP client and configuration properties.
     *
     * @param providerConfig     Provider-specific configuration (apikey, endpoint, model, etc.)
     */
    void init(Map<String, String> providerConfig);

    /**
     * The type identifier for this provider (e.g., "OPENAI", "MISTRAL").
     *
     * @return A unique string identifier.
     */
    String getType();

    /**
     * Returns the embedding vector for the given input text.
     *
     * @param input The text to embed.
     * @return A float array representing the embedding.
     * @throws IOException if an error occurs during the request.
     */
    float[] getEmbedding(String input) throws IOException;

    /**
     * Returns the embedding vectors for the given input text array.
     *
     * @param input The texts to embed.
     * @return A float array representing the embedding.
     * @throws IOException if an error occurs during the request.
     */
    List<float[]> getEmbeddings(List<String> input) throws IOException;
}

