package org.wso2.apim.policies.mediation.ai.semantic.cache;

import java.io.IOException;

public interface VectorDBProvider {

    /**
     * Creates a new index in the vector database with the given identifier.
     *
     * @param indexId The unique identifier for the index.
     */
    void createIndex(String indexId);

    /**
     * Stores a response along with its embedding in the vector database.
     *
     * @param response The response to store.
     * @throws IOException if an error occurs during the storage operation.
     */
    void store(float[] embeddings, CachableResponse response) throws IOException;

    /**
     * Retrieves the most relevant response from the vector database for the given embedding.
     *
     * @param embeddings The embedding to use for similarity search.
     * @return The most relevant cached response.
     * @throws IOException if an error occurs during the retrieval operation.
     */
    CachableResponse retrieve(float[] embeddings) throws IOException;

}
