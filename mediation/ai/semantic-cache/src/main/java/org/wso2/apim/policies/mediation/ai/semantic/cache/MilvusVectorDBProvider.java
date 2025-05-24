package org.wso2.apim.policies.mediation.ai.semantic.cache;

import com.google.gson.JsonObject;
import com.google.gson.Gson;
import io.milvus.param.Constant;
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
    private final MilvusClientV2 client;
    private String collectionName;
    private final int dimension;
    private final double threshold;
    private final String distanceMetric;
    private final Gson gson = new Gson();

    private static final String EMBEDDING_FIELD = "embedding";
    private static final String RESPONSE_FIELD = "response";

    public MilvusVectorDBProvider(MilvusClientV2 client, int dimension,
                                  String distanceMetric, double threshold) {
        this.client = client;
        this.dimension = dimension;
        this.distanceMetric = distanceMetric;
        this.threshold = threshold;
    }

    @Override
    public void createIndex(String indexId) {
        this.collectionName = indexId;

        // Drop collection if exists
        HasCollectionReq hasCollectionReq = HasCollectionReq.builder()
                .collectionName(this.collectionName)
                .build();
        boolean hasCollection = client.hasCollection(hasCollectionReq);
        if (hasCollection) {
            DropCollectionReq dropParam = DropCollectionReq.builder()
                    .collectionName(this.collectionName)
                    .build();
            client.dropCollection(dropParam);
        }

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
                .fieldName("embedding")
                .dataType(DataType.FloatVector)
                .dimension(dimension)
                .build());

        schema.addField(AddFieldReq.builder()
                .fieldName("response")
                .dataType(DataType.VarChar)
                .maxLength(65535)
                .isNullable(false)
                .build());

        // Create index
        IndexParam index = IndexParam.builder()
                .fieldName("embedding")
                .indexType(IndexParam.IndexType.HNSW)
                .indexName(indexId)
                .metricType(IndexParam.MetricType.L2)
                .extraParams(Map.of(
                        "M", 64,  // Maximum number of neighbors per node
                        "efConstruction", 100  // Number of candidates during construction
                ))
                .build();

        // Create collection
        CreateCollectionReq customizedSetupReq = CreateCollectionReq.builder()
                .collectionName(collectionName)
                .collectionSchema(schema)
                .property(Constant.TTL_SECONDS, "60")
                .indexParams(List.of(index))
                .build();

        client.createCollection(customizedSetupReq);
    }

    @Override
    public void store(float[] embeddings, CachableResponse response) {
        // Prepare insert data
        String id = UUID.randomUUID().toString();
        String responseJson = gson.toJson(response);

        // Construct row as JsonObject
        JsonObject row = new JsonObject();
        row.addProperty("id", id);
        row.addProperty("created_at", System.currentTimeMillis() / 1000);
        row.add("embedding", gson.toJsonTree(embeddings));
        row.addProperty("response", responseJson);

        InsertReq insertReq = InsertReq.builder()
                .collectionName(collectionName)
                .data(Collections.singletonList(row))
                .build();
        client.insert(insertReq);
    }

    @Override
    public CachableResponse retrieve(float[] embeddings) {
        // Perform the search
        SearchResp searchR = client.search(SearchReq.builder()
                .collectionName(collectionName)
                .data(Collections.singletonList(new FloatVec(embeddings)))
                .topK(1)
                .outputFields(Collections.singletonList("response"))
                .filter("created_at >= " + (System.currentTimeMillis() / 1000 - 60))
                .build());

        // Prepare the search vectors as List<List<Float>>
        List<SearchResp.SearchResult> result = searchR.getSearchResults().get(0);

        if (result.isEmpty()) return null;

        Map<String, Object> topResult = result.get(0).getEntity();

        // Optional: use the score to filter by a similarity threshold
        float score = 1.0f/(result.get(0).getScore()+1);
        if (score < this.threshold) return null;

        return gson.fromJson((String) topResult.get("response"), CachableResponse.class);
    }

}
