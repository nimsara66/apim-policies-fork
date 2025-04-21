package org.wso2.apim.policies.mediation.ai.aws.bedrock.guardrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AWSBedrockUtils {
    private static final Log logger = LogFactory.getLog(AWSBedrockUtils.class);

    /**
     * Extracts JSON content from the message context.
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    /**
     * Makes an HTTP POST request to AWS Bedrock Guardrail API.
     *
     * @param url The Bedrock API endpoint URL
     * @param payload The JSON payload
     * @param headers The authentication headers
     * @return The response as a JsonNode
     * @throws Exception If the request fails
     */
    public static String makeBedrockRequest(
            String url, String payload, Map<String, String> headers, Integer timeout) throws Exception {

        // Create request config with the specified timeout (in milliseconds)
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(timeout)
                .setSocketTimeout(timeout)
                .setConnectionRequestTimeout(timeout)
                .build();

        try (CloseableHttpClient httpClient = HttpClients.custom().setDefaultRequestConfig(requestConfig).build()) {

            HttpPost httpPost = new HttpPost(new URI(url));

            // Set headers
            httpPost.setHeader(AWSBedrockConstants.CONTENT_TYPE_HEADER, "application/json");
            for (Map.Entry<String, String> header : headers.entrySet()) {
                httpPost.setHeader(header.getKey(), header.getValue());
            }

            // Set request body
            StringEntity entity = new StringEntity(payload, StandardCharsets.UTF_8);
            httpPost.setEntity(entity);

            if (logger.isDebugEnabled()) {
                logger.debug("Sending request to AWS Bedrock Guardrail");
            }

            // Execute the request
            HttpResponse response = httpClient.execute(httpPost);

            // Process response
            HttpEntity responseEntity = response.getEntity();
            String responseBody = EntityUtils.toString(responseEntity);

            // Check response status
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode >= 200 && statusCode < 300) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Received successful response from AWS Bedrock Guardrail");
                }
                return responseBody;
            } else {
                logger.error("AWS Bedrock Guardrail request failed with status code: " + statusCode);
                logger.error("Response: " + responseBody);
                return null;
            }
        }
    }

    /**
     * Creates the request payload for AWS Bedrock Guardrail API.
     *
     * @param content The content to be guarded by Bedrock
     * @return JSON payload for Bedrock API
     * @throws Exception If payload creation fails
     */
    public static String createBedrockRequestPayload(String content, boolean isResponse) throws Exception {

        if (logger.isDebugEnabled()) {
            logger.debug("Creating Bedrock Guardrail request payload");
        }

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> requestMap = new TreeMap<>();

        // Set source based on whether it's a request or response
        requestMap.put(AWSBedrockConstants.BEDROCK_GUARDRAIL_SOURCE_HEADER, isResponse
                ? AWSBedrockConstants.BEDROCK_GUARDRAIL_RESPONSE_SOURCE
                : AWSBedrockConstants.BEDROCK_GUARDRAIL_REQUEST_SOURCE);

        // Create content array with text object
        Map<String, Object> textObj = new TreeMap<>();
        textObj.put(AWSBedrockConstants.BEDROCK_GUARDRAIL_TEXT, content);

        Map<String, Object> contentItem = new TreeMap<>();
        contentItem.put(AWSBedrockConstants.BEDROCK_GUARDRAIL_TEXT, textObj);

        // Add to content array
        requestMap.put(AWSBedrockConstants.BEDROCK_GUARDRAIL_CONTENT, new Object[]{contentItem});

        if (logger.isDebugEnabled()) {
            logger.debug("Successfully created Bedrock Guardrail request payload");
        }

        return mapper.writeValueAsString(requestMap);
    }

    public static Map<String, String> generateAWSSignature(
            String host, String method, String uri, String queryString, String payload,
            String accessKey, String secretKey, String region, String sessionToken) throws Exception {

        if (logger.isDebugEnabled()) {
            logger.debug("Generating AWS Signature V4 for Bedrock Guardrail request");
        }

        // Step 1: Create date stamps
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String amzDate = DateTimeFormatter.ofPattern(AWSBedrockConstants.AMZ_DATE_FORMAT).format(now);
        String dateStamp = DateTimeFormatter.ofPattern(AWSBedrockConstants.DATE_FORMAT).format(now);

        // Step 2: Create canonical headers
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.put(AWSBedrockConstants.HOST_HEADER, host);
        headers.put(AWSBedrockConstants.AMZ_DATE_HEADER, amzDate);
        if (sessionToken != null && !sessionToken.isEmpty()) {
            headers.put(AWSBedrockConstants.AMZ_SECURITY_TOKEN_HEADER, sessionToken);
        }

        // Add content-type for POST request with JSON payload
        headers.put(AWSBedrockConstants.CONTENT_TYPE_HEADER, "application/json");

        // Calculate payload hash
        String payloadHash = hash(payload);
        headers.put(AWSBedrockConstants.AMZ_CONTENT_SHA_HEADER, payloadHash);

        // Build canonical headers string and signed headers list
        StringBuilder canonicalHeaders = new StringBuilder();
        StringBuilder signedHeaders = new StringBuilder();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            canonicalHeaders.append(entry.getKey().toLowerCase()).append(":").append(entry.getValue()).append("\n");
            signedHeaders.append(entry.getKey().toLowerCase()).append(";");
        }
        // Remove trailing semicolon
        if (signedHeaders.length() > 0) {
            signedHeaders.setLength(signedHeaders.length() - 1);
        }

        // Step 3: Create canonical request
        String canonicalRequest = method + "\n" +
                uri + "\n" +
                queryString + "\n" +
                canonicalHeaders + "\n" +
                signedHeaders + "\n" +
                payloadHash;

        // Step 4: Create string to sign
        String algorithm = AWSBedrockConstants.AWS4_ALGORITHM;
        // String region = "ap-southeast-2";
        String credentialScope = dateStamp + "/" + region + "/" + AWSBedrockConstants.BEDROCK_SERVICE + "/" +
                AWSBedrockConstants.AWS4_REQUEST;
        String stringToSign = algorithm + "\n" + amzDate + "\n" + credentialScope + "\n" + hash(canonicalRequest);

        // Step 5: Calculate signature
        byte[] signingKey = getSignatureKey(secretKey, dateStamp, region, AWSBedrockConstants.BEDROCK_SERVICE);
        String signature = bytesToHex(hmacSHA256(stringToSign, signingKey));

        // Step 6: Create authorization header
        String authorizationHeader = algorithm + " " +
                AWSBedrockConstants.AWS4_CREDENTIAL + "=" + accessKey + "/" + credentialScope + ", " +
                AWSBedrockConstants.AWS4_SIGNED_HEADERS + "=" + signedHeaders + ", "
                + AWSBedrockConstants.AWS4_SIGNATURE + "=" + signature;

        // Create result map with all required headers
        Map<String, String> authHeaders = new HashMap<>(headers);
        authHeaders.put("Authorization", authorizationHeader);

        if (logger.isDebugEnabled()) {
            logger.debug("Successfully generated AWS Signature V4 for Bedrock Guardrail request");
        }

        return authHeaders;
    }

    // Helper method for SHA-256 hashing
    public static String hash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(digest);
    }

    // Helper method to get signature key
    public static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmacSHA256(dateStamp, kSecret);
        byte[] kRegion = hmacSHA256(regionName, kDate);
        byte[] kService = hmacSHA256(serviceName, kRegion);
        return hmacSHA256("aws4_request", kService);
    }

    // Helper method for HMAC-SHA256
    public static byte[] hmacSHA256(String data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    // Helper method to convert bytes to hex
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
