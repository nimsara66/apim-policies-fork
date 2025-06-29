package org.wso2.apim.policies.mediation.ai.rag.injector;

import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.util.List;

public interface EmbeddingProvider {
    /**
     * Returns the embedding vector for the given input text.
     *
     * @param input The text to embed.
     * @return A float array representing the embedding.
     * @throws IOException if an error occurs during the request.
     */
    JsonNode getEmbedding(String input) throws IOException;

    /**
     * Returns the embedding vectors for the given input text array.
     *
     * @param input The texts to embed.
     * @return A float array representing the embedding.
     * @throws IOException if an error occurs during the request.
     */
    List<float[]> getEmbeddings(List<String> input) throws IOException;
}

