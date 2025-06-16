package org.wso2.apim.policies.mediation.ai.semantic.cache;

public enum VectorDBProviderType {
    REDIS_STACK("redis-stack"),
    MILVUS("milvus");

    private final String type;

    VectorDBProviderType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public static VectorDBProviderType fromString(String value) {
        for (VectorDBProviderType t : values()) {
            if (t.type.equalsIgnoreCase(value)) {
                return t;
            }
        }
        throw new IllegalArgumentException("Unknown vector db provider type: " + value);
    }
}
