package org.wso2.apim.policies.mediation.ai.semantic.cache;

import java.io.IOException;
import java.util.Map;

public interface VectorDBProvider {

    /**
     * Initializes the vector DB provider with configuration.
     *
     * @param config A map of provider-specific configuration values.
     */
    void init(Map<String, String> config);

    /**
     * Returns the type identifier of this provider (e.g., "REDIS", "PINECONE").
     */
    String getType();

    /**
     * Creates a new index in the vector database with the given identifier.
     *
     */
    void createIndex(Map<String, String> config);

    /**
     * Stores a response along with its embedding in the vector database.
     *
     * @param response The response to store.
     * @throws IOException if an error occurs during the storage operation.
     */
    void store(float[] embeddings, CachableResponse response, Map<String, String> filter) throws IOException;

    /**
     * Retrieves the most relevant response from the vector database for the given embedding.
     *
     * @param embeddings The embedding to use for similarity search.
     * @return The most relevant cached response.
     * @throws IOException if an error occurs during the retrieval operation.
     */
    CachableResponse retrieve(float[] embeddings, Map<String, String> filter) throws IOException;

}
