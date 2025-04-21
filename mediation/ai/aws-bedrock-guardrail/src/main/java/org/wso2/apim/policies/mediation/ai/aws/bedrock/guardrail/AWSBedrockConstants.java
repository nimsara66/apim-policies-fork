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
    public static String AWS4_ALGORITHM = "AWS4-HMAC-SHA256";
    public static String AWS4_REQUEST = "aws4_request";
    public static String AWS4_CREDENTIAL = "Credential";
    public static String AWS4_SIGNED_HEADERS = "SignedHeaders";
    public static String AWS4_SIGNATURE = "Signature";
    public static String BEDROCK_GUARDRAIL_REQUEST_SOURCE = "INPUT";
    public static String BEDROCK_GUARDRAIL_RESPONSE_SOURCE = "OUTPUT";
    public static String BEDROCK_GUARDRAIL_SOURCE_HEADER = "source";
    public static String BEDROCK_GUARDRAIL_TEXT = "text";
    public static String BEDROCK_GUARDRAIL_CONTENT = "content";
    public static int BEDROCK_GUARDRAIL_ERROR_CODE = 446;
    public static String ERROR_TYPE = "ERROR_TYPE";
    public static String CUSTOM_HTTP_SC = "CUSTOM_HTTP_SC";
    public static String FAULT_SEQUENCE_KEY = "custom_fault";
}
