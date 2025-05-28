/*
 *
 * Copyright (c) 2025 WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.wso2.apim.policies.mediation.ai.semantic.cache;

public class SemanticCacheConstants {
    public static String TEXT_CLEAN_REGEX = "^\"|\"$";
    public static final String HTTP_PROTOCOL_TYPE = "HTTP";
    public static final String ALL = "*";
    public static final String ANY_RESPONSE_CODE = ".*";
    public static final int DEFAULT_SIZE = -1;
    public static final boolean DEFAULT_ADD_AGE_HEADER = false;
    public static final boolean DEFAULT_ENABLE_CACHE_CONTROL = false;
    public static final String REQUEST_EMBEDDINGS = "requestEmbeddings";

    public static final String NO_STORE_STRING = "no-store";
    public static final String CACHE_KEY = "cacheKey";
    public static final String DATE_PATTERN = "EEE, dd MMM yyyy HH:mm:ss z";
}
