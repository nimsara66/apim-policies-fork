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

package org.wso2.apim.policies.mediation.ai.aws.bedrock.guardrail;

public class AWSBedrockConstants {
    public static String BEDROCK_RUNTIME = "bedrock-runtime";
    public static String BEDROCK_HOST = "amazonaws.com";
    public static String GUARDRAIL_SERVICE = "guardrail";
    public static String BEDROCK_SERVICE = "bedrock";
    public static String GUARDRAIL_VERSION = "version";
    public static String GUARDRAIL_CALL = "apply";
    public static String GUARDRAIL_PROTOCOL = "https";
    public static String AWS4_METHOD = "POST";
    public static String AMZ_DATE_FORMAT = "yyyyMMdd'T'HHmmss'Z'";
    public static String DATE_FORMAT = "yyyyMMdd";
    public static String HOST_HEADER = "host";
    public static String AMZ_DATE_HEADER = "x-amz-date";
    public static String AMZ_SECURITY_TOKEN_HEADER = "x-amz-security-token";
    public static String CONTENT_TYPE_HEADER = "content-type";
    public static String AMZ_CONTENT_SHA_HEADER = "x-amz-content-sha256";
    public static String AWS4 = "AWS4";
    public static String AWS4_ALGORITHM = "AWS4-HMAC-SHA256";
    public static String AWS4_REQUEST = "aws4_request";
    public static String AWS4_CREDENTIAL = "Credential";
    public static String AWS4_SIGNED_HEADERS = "SignedHeaders";
    public static String AWS4_SIGNATURE = "Signature";
    public static String BEDROCK_GUARDRAIL_REQUEST_SOURCE = "INPUT";
    public static String BEDROCK_GUARDRAIL_RESPONSE_SOURCE = "OUTPUT";
    public static String BEDROCK_GUARDRAIL_SOURCE_HEADER = "source";
    public static String BEDROCK_GUARDRAIL_TEXT = "text";
    public static String BEDROCK_GUARDRAIL_OUTPUT = "output";
    public static String BEDROCK_GUARDRAIL_CONTENT = "content";
    public static String BEDROCK_GUARDRAIL_SIP = "sensitiveInformationPolicy";
    public static String BEDROCK_GUARDRAIL_PII_ENTITIES = "piiEntities";
    public static String BEDROCK_GUARDRAIL_PII_REGEXES = "regexes";
    public static String BEDROCK_GUARDRAIL_PII_ACTION = "action";
    public static String BEDROCK_GUARDRAIL_PII_MATCH = "match";
    public static String BEDROCK_GUARDRAIL_PII_TYPE = "type";
    public static String BEDROCK_GUARDRAIL_PII_NAME = "name";
    public static int GUARDRAIL_ERROR_CODE = 446;
    public static String ERROR_TYPE = "ERROR_TYPE";
    public static String CUSTOM_HTTP_SC = "CUSTOM_HTTP_SC";
    public static String FAULT_SEQUENCE_KEY = "custom_fault";
    public static String JSON_CLEAN_REGEX = "^\"|\"$";

    public static String ASSESSMENT_ACTION = "action";
    public static String ASSESSMENT_REASON = "actionReason";
    public static String INTERVENING_GUARDRAIL = "interveningGuardrail";
    public static String ASSESSMENTS = "assessments";

    public static int GUARDRAIL_APIM_EXCEPTION_CODE = 900514;
    public static int APIM_INTERNAL_EXCEPTION_CODE = 900967;
    public static String AWS_BEDROCK_GUARDRAIL = "AWS_BEDROCK_GUARDRAIL";
    public static int MAX_RETRY_COUNT = 3;
}
