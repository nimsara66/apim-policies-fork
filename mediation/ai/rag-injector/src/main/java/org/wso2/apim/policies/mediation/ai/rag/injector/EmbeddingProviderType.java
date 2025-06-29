package org.wso2.apim.policies.mediation.ai.rag.injector;

public enum EmbeddingProviderType {
    MISTRAL("mistral"),
    OPENAI("openai"),
    AZURE_OPENAI("azure-openai");

    private final String type;

    EmbeddingProviderType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }

    public static EmbeddingProviderType fromString(String value) {
        for (EmbeddingProviderType t : values()) {
            if (t.type.equalsIgnoreCase(value)) {
                return t;
            }
        }
        throw new IllegalArgumentException("Unknown embedding provider type: " + value);
    }
}

