package org.wso2.apim.policies.mediation.ai.semantic.cache;

import com.google.gson.JsonObject;
import com.google.gson.Gson;
import io.milvus.param.Constant;
import io.milvus.v2.client.ConnectConfig;
import io.milvus.v2.client.MilvusClientV2;
import io.milvus.v2.common.DataType;
import io.milvus.v2.common.IndexParam;
import io.milvus.v2.service.collection.request.AddFieldReq;
import io.milvus.v2.service.collection.request.CreateCollectionReq;
import io.milvus.v2.service.collection.request.DropCollectionReq;
import io.milvus.v2.service.collection.request.HasCollectionReq;
import io.milvus.v2.service.vector.request.InsertReq;
import io.milvus.v2.service.vector.request.SearchReq;
import io.milvus.v2.service.vector.request.data.FloatVec;
import io.milvus.v2.service.vector.response.SearchResp;

import java.util.*;

public class MilvusVectorDBProvider implements VectorDBProvider {
    private static final String EMBEDDING_FIELD = "embedding";
    private static final String RESPONSE_FIELD = "response";

    private MilvusClientV2 client;
    private String collectionName;
    private int dimension;
    private int ttl;
    private final Gson gson = new Gson();

    @Override
    public void init(Map<String, String> providerConfig) {
        String host = providerConfig.get("host");
        String port = providerConfig.get("port");
        String embeddingDimension = providerConfig.get("embedding_dimension");

        if (host == null || port == null || embeddingDimension == null) {
            throw new IllegalArgumentException(
                    "Missing required Milvus configuration: 'host', 'port', or 'collection_name'");
        }

        this.collectionName = SemanticCacheConstants.VECTOR_INDEX_PREFIX + embeddingDimension;
        this.dimension = Integer.parseInt(embeddingDimension);
        this.ttl = Integer.parseInt(providerConfig.getOrDefault("ttl", "36000")); // Default to 1 hour

        ConnectConfig connectConfig = ConnectConfig.builder()
                .uri("http://" + host + ":" + port)
                .build();

        this.client = new MilvusClientV2(connectConfig);
    }

    @Override
    public String getType() {
        return "MILVUS";
    }

    @Override
    public void createIndex(Map<String, String> providerConfig) {
        // Return if exists
        HasCollectionReq hasCollectionReq = HasCollectionReq.builder()
                .collectionName(this.collectionName)
                .build();
        if (client.hasCollection(hasCollectionReq)) return;

        // Create schema
        CreateCollectionReq.CollectionSchema schema = MilvusClientV2.CreateSchema();
        schema.addField(AddFieldReq.builder()
                .fieldName("id")
                .dataType(DataType.VarChar)
                .autoID(false)
                .maxLength(36)
                .isPrimaryKey(true)
                .build());

        schema.addField(AddFieldReq.builder()
                .fieldName("created_at")
                .dataType(DataType.Int64)
                .build());

        schema.addField(AddFieldReq.builder()
                .fieldName("api_id")
                .dataType(DataType.VarChar)
                .maxLength(36)
                .build());

        schema.addField(AddFieldReq.builder()
                .fieldName(EMBEDDING_FIELD)
                .dataType(DataType.FloatVector)
                .dimension(this.dimension)
                .build());

        schema.addField(AddFieldReq.builder()
                .fieldName(RESPONSE_FIELD)
                .dataType(DataType.VarChar)
                .maxLength(65535)
                .isNullable(false)
                .build());

        // Create index
        IndexParam index = IndexParam.builder()
                .fieldName(EMBEDDING_FIELD)
                .indexType(IndexParam.IndexType.HNSW)
                .indexName(this.collectionName + "_index")
                .metricType(IndexParam.MetricType.L2)
                .extraParams(Map.of(
                        "M", 64,  // Maximum number of neighbors per node
                        "efConstruction", 100  // Number of candidates during construction
                ))
                .build();

        // Create collection
        CreateCollectionReq customizedSetupReq = CreateCollectionReq.builder()
                .collectionName(this.collectionName)
                .collectionSchema(schema)
                .property(Constant.TTL_SECONDS, String.valueOf(this.ttl))
                .indexParams(List.of(index))
                .build();

        client.createCollection(customizedSetupReq);
    }

    @Override
    public void store(float[] embeddings, CachableResponse response, Map<String, String> filter) {
        // Prepare insert data
        String id = UUID.randomUUID().toString();
        String responseJson = gson.toJson(response);

        // Construct row as JsonObject
        JsonObject row = new JsonObject();
        row.addProperty("id", id);
        row.addProperty("created_at", System.currentTimeMillis() / 1000);
        row.addProperty("api_id", filter.get("api_id"));
        row.add(EMBEDDING_FIELD, gson.toJsonTree(embeddings));
        row.addProperty(RESPONSE_FIELD, responseJson);

        InsertReq insertReq = InsertReq.builder()
                .collectionName(collectionName)
                .data(Collections.singletonList(row))
                .build();
        client.insert(insertReq);
    }

    @Override
    public CachableResponse retrieve(float[] embeddings, Map<String, String> filter) {
        // Perform the search
        SearchResp searchR = client.search(SearchReq.builder()
                .collectionName(collectionName)
                .data(Collections.singletonList(new FloatVec(embeddings)))
                .topK(1)
                .outputFields(Collections.singletonList(RESPONSE_FIELD))
                .filter("api_id == '" + filter.get("api_id") + "'")
                .filter("created_at >= " + (System.currentTimeMillis() / 1000 - this.ttl))
                .build());

        // Prepare the search vectors as List<List<Float>>
        List<SearchResp.SearchResult> result = searchR.getSearchResults().get(0);

        if (result.isEmpty()) return null;

        Map<String, Object> topResult = result.get(0).getEntity();

        // Optional: use the score to filter by a similarity threshold
        float score = 100f/(result.get(0).getScore()+1);
        if (score < Integer.parseInt(filter.get("threshold"))) return null;

        return gson.fromJson((String) topResult.get(RESPONSE_FIELD), CachableResponse.class);
    }

}
