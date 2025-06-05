package org.wso2.apim.policies.mediation.ai.semantic.prompt.guard;

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
     * Return the embedding dimension for the given embedding model.
     * Calculate embedding length based on the generated embedding for empty string
     *
     * @return The dimension of the embedding vector.
     */
    int getEmbeddingDimension() throws IOException;

    /**
     * Returns the embedding vector for the given input text.
     *
     * @param input The text to embed.
     * @return A float array representing the embedding.
     * @throws IOException if an error occurs during the request.
     */
    float[] getEmbedding(String input) throws IOException;
}

