package org.wso2.apim.policies.mediation.ai.semantic.prompt.guard;

import java.io.IOException;

public interface EmbeddingProvider {
    /**
     * Returns the embedding vector for the given input text.
     *
     * @param input The text to embed.
     * @return A float array representing the embedding.
     * @throws IOException if an error occurs during the request.
     */
    float[] getEmbedding(String input) throws IOException;
}

