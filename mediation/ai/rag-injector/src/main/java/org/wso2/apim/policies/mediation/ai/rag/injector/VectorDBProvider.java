package org.wso2.apim.policies.mediation.ai.rag.injector;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.logging.Log;

import java.io.IOException;
import java.util.Map;

public interface VectorDBProvider {

    /**
     * Retrieves the most relevant response from the vector database for the given embedding.
     *
     * @param embeddings The embedding to use for similarity search.
     * @return The most relevant cached response.
     * @throws IOException if an error occurs during the retrieval operation.
     */
    String retrieve(JsonNode embeddings, Map<String, String> options, Log logger) throws IOException;
}
