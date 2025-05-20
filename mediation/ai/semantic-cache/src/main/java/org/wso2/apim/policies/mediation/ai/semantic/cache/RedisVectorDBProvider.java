package org.wso2.apim.policies.mediation.ai.semantic.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import redis.clients.jedis.UnifiedJedis;
import redis.clients.jedis.search.Document;
import redis.clients.jedis.search.FTCreateParams;
import redis.clients.jedis.search.IndexDataType;
import redis.clients.jedis.search.Query;
import redis.clients.jedis.search.SearchResult;
import redis.clients.jedis.search.schemafields.SchemaField;
import redis.clients.jedis.search.schemafields.VectorField;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class RedisVectorDBProvider implements VectorDBProvider {
    private static final Log logger = LogFactory.getLog(RedisVectorDBProvider.class);
    private final UnifiedJedis jedis;
    private final int ttlSeconds;
    private final int dimension;
    private final double threshold;
    private final String distanceMetric;
    private String indexId;
    private static final String KEY_PREFIX = "doc:";
    private static final String EMBEDDING_FIELD = "embedding";
    private static final String RESPONSE_FIELD = "response";

    public RedisVectorDBProvider(UnifiedJedis jedis, int ttlSeconds, int dimension,
                                 String distanceMetric, double threshold) {
        this.jedis = jedis;
        this.ttlSeconds = ttlSeconds;
        this.dimension = dimension;
        this.distanceMetric = distanceMetric;
        this.threshold = threshold;
    }

    @Override
    public void createIndex(String indexId) {
        try {
            // Check if index exists
            jedis.ftInfo(indexId);

            // If no exception, index exists — drop it (along with associated documents)
            jedis.ftDropIndex(indexId);
        } catch (Exception e) {
            logger.info("Index {} does not exist, creating a new one.");
        }

        SchemaField[] schema = {
                VectorField.builder()
                        .fieldName(EMBEDDING_FIELD)
                        .algorithm(VectorField.VectorAlgorithm.HNSW)
                        .attributes(
                                Map.of(
                                        "TYPE", "FLOAT32",
                                        "DIM", this.dimension,
                                        "DISTANCE_METRIC", this.distanceMetric
                                )
                        )
                        .build()
        };

        jedis.ftCreate(indexId,
                FTCreateParams.createParams()
                        .addPrefix("doc:")
                        .on(IndexDataType.HASH),
                schema
        );
        this.indexId = indexId;
    }

    @Override
    public void store(float[] embeddings, CachableResponse response) throws IOException {
        // Convert embedding to binary
        byte[] embeddingBytes = floatArrayToByteArray(embeddings);

        // Serialize response object
        byte[] responseBytes = serializeObject(response);

        String docId = UUID.randomUUID().toString();
        String redisKey = KEY_PREFIX + docId;

        Map<String, Object> doc = new HashMap<>();
        doc.put(EMBEDDING_FIELD, embeddingBytes);
        doc.put(RESPONSE_FIELD, responseBytes);

        jedis.hset(redisKey.getBytes(), toBinaryMap(doc));
        if (this.ttlSeconds > 0) {
            jedis.expire(redisKey.getBytes(), this.ttlSeconds);
        }
    }

    @Override
    public CachableResponse retrieve(float[] embeddings) throws IOException {
        // Convert float[] embedding to byte[] as Redis expects binary blob
        byte[] blob = floatArrayToByteArray(embeddings);
        int K = 1;

        // Build the query
        String knnQuery = String.format("*=>[KNN $K @%s $BLOB AS score]", EMBEDDING_FIELD);
        Query query = new Query(knnQuery)
                .returnFields(RESPONSE_FIELD, "score")
                .addParam("K", K)
                .addParam("BLOB", blob)
                .dialect(2);

        // Execute search
        SearchResult result = jedis.ftSearch(indexId, query);
        if (result.getTotalResults() == 0) return null;

        Document doc = result.getDocuments().get(0);

        // Optional: use the score to filter by a similarity threshold
        Double score = doc.getScore();
        if (score < this.threshold) return null;

        // Deserialize binary response
        byte[] responseBytes = jedis.hget(doc.getId().getBytes(), RESPONSE_FIELD.getBytes());
        return (CachableResponse) deserializeObject(responseBytes);
    }

    private byte[] floatArrayToByteArray(float[] floats) {
        ByteBuffer buffer = ByteBuffer.allocate(floats.length * Float.BYTES);
        for (float f : floats) {
            buffer.putFloat(f);
        }
        return buffer.array();
    }

    private byte[] serializeObject(CachableResponse response) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = new ObjectOutputStream(bos);
        out.writeObject(response);
        out.close();
        return bos.toByteArray();
    }

    private Object deserializeObject(byte[] data) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        try (ObjectInputStream in = new ObjectInputStream(bis)) {
            return in.readObject();
        } catch (ClassNotFoundException e) {
            throw new IOException("Deserialization failed", e);
        }
    }

    private Map<byte[], byte[]> toBinaryMap(Map<String, Object> map) {
        Map<byte[], byte[]> binaryMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            binaryMap.put(entry.getKey().getBytes(), (byte[]) entry.getValue());
        }
        return binaryMap;
    }
}
