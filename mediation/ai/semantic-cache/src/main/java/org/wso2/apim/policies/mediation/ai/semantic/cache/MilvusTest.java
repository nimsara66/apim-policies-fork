package org.wso2.apim.policies.mediation.ai.semantic.cache;

import io.milvus.v2.client.ConnectConfig;
import io.milvus.v2.client.MilvusClientV2;

public class MilvusTest {
    public static void main(String[] args) {
        try {
            ConnectConfig connectConfig = ConnectConfig.builder()
                    .uri("http://10.100.1.130:19530")
                    .build();
            MilvusClientV2 milvusClient = new MilvusClientV2(connectConfig);
            System.out.println(milvusClient);
            System.out.println("Success!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

