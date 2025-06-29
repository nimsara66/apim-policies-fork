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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class providing functionalities to interact with the AWS Bedrock Guardrail API.
 * This class offers methods for extracting JSON content from Axis2 message contexts,
 * performing exact string replacements, making HTTP POST requests to the Bedrock API,
 * creating request payloads, and generating AWS Signature Version 4 for authentication.
 * It also includes functionality to generate temporary AWS credentials using AssumeRole
 * for secure interaction with the Bedrock service.
 */

public class AWSBedrockUtils {
    private static final Log logger = LogFactory.getLog(AWSBedrockUtils.class);

    /**
     * Extracts the JSON payload as a String from the Axis2 {@link MessageContext}.
     * This method is specifically designed to retrieve the JSON content of the message
     * body when working within an Axis2 environment.
     *
     * @param messageContext The Axis2 {@link MessageContext} containing the request or response.
     * @return The JSON payload as a String, or null if an error occurs during extraction.
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    /**
     * Replaces all exact occurrences of a target string within a given content string
     * with a specified replacement string. This method ensures that only whole,
     * non-overlapping matches of the target are replaced, treating it as a literal string.
     * Regular expression special characters within the target string are automatically escaped.
     *
     * @param content     The original string in which replacements will be made.
     * @param target      The exact string to be replaced. Regular expression metacharacters
     * in this string are treated literally.
     * @param replacement The string to replace all occurrences of the target.
     * @return A new string with all exact matches of the target replaced by the replacement.
     */
    public static String replaceExactMatch(String content, String target, String replacement) {
        // Escape regex special characters in the match string
        String escapedTarget = Pattern.quote(target);
        // Replace all exact matches
        return content.replaceAll(escapedTarget, Matcher.quoteReplacement(replacement));
    }

    /**
     * Makes an HTTP POST request to the specified AWS Bedrock Guardrail API endpoint.
     * This method handles setting the necessary headers, request body, and processing
     * the response. It also includes a configurable timeout for the connection, socket,
     * and connection request.
     *
     * @param url     The complete URL of the AWS Bedrock Guardrail API endpoint.
     * @param payload The JSON payload to be sent in the request body.
     * @param headers A {@code Map} of HTTP headers to be included in the request,
     * typically containing authentication information.
     * waiting for data (socket timeout), and acquiring a connection
     * from the connection manager.
     * @return The response body as a String if the request is successful (HTTP status
     * code 2xx), otherwise null.
     * @throws APIManagementException If an error occurs during the HTTP request execution, such as
     * network issues or invalid parameters.
     */
    public static String makeBedrockRequest(String url, String payload, Map<String, String> headers)
            throws APIManagementException {

        HttpClient httpClient = APIUtil.getHttpClient(url);
        HttpPost httpPost = new HttpPost(url);
        // Set headers
        httpPost.setHeader(AWSBedrockConstants.CONTENT_TYPE_HEADER, "application/json");
        for (Map.Entry<String, String> header : headers.entrySet()) {
            httpPost.setHeader(header.getKey(), header.getValue());
        }
        // Set request body
        StringEntity entity = new StringEntity(payload, StandardCharsets.UTF_8);
        httpPost.setEntity(entity);

        try (CloseableHttpResponse response = APIUtil.executeHTTPRequestWithRetries(httpPost, httpClient)) {
            return EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        } catch (APIManagementException | IOException e) {
            return "";
        }
    }

    /**
     * Creates the JSON request payload for the AWS Bedrock Guardrail API. The payload
     * structure includes the content to be processed and a source indicator to distinguish
     * between requests and responses being sent to the Guardrail API.
     *
     * @param content    The text content that needs to be evaluated by the Bedrock Guardrail.
     * @param isResponse A boolean flag indicating whether the content originates from an
     * application response (true) or a user request (false). This helps
     * the Guardrail service apply appropriate rules.
     * @return A JSON string representing the request payload for the Bedrock API.
     * @throws Exception If an error occurs during the creation or serialization of the JSON payload.
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

    /**
     * Generates the necessary AWS Signature Version 4 headers for authenticating requests
     * to the AWS Bedrock Guardrail API. This method constructs the signature based on
     * the provided request parameters and AWS credentials.
     *
     * @param host         The hostname of the AWS Bedrock Guardrail API endpoint.
     * @param method       The HTTP method of the request (e.g., "POST").
     * @param service      The AWS service identifier (e.g., "bedrock").
     * @param uri          The URI path of the API endpoint.
     * @param queryString  The query string parameters of the request (can be null or empty).
     * @param payload      The request payload as a String (can be null or empty for GET requests).
     * @param accessKey    The AWS access key ID.
     * @param secretKey    The AWS secret access key.
     * @param region       The AWS region for the Bedrock service.
     * @param sessionToken The AWS session token, if using temporary credentials (can be null or empty).
     * @return A {@code Map} containing the HTTP headers required for AWS Signature V4 authentication,
     * including the "Authorization" header.
     * @throws Exception If an error occurs during the signature generation process, such as
     * problems with hashing or HMAC calculation.
     */
    public static Map<String, String> generateAWSSignature(
            String host, String method, String service, String uri, String queryString, String payload,
            String accessKey, String secretKey, String region, String sessionToken) throws Exception {

        if (logger.isDebugEnabled()) {
            logger.debug("AWSBedrockGuardrail: Generating AWS Signature V4 for Bedrock Guardrail request");
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

        String payloadHash = payload != null? hash(payload): hash("");
        if (payload != null && !payload.isEmpty()) {
            // Add content-type and x-amz-content-sha25 for POST request with JSON payload
            headers.put(AWSBedrockConstants.CONTENT_TYPE_HEADER, "application/json");
            headers.put(AWSBedrockConstants.AMZ_CONTENT_SHA_HEADER, payloadHash);
        }

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
        // For STS GET requests, we need to sort and encode query parameters
        String canonicalQueryString = "";
        if (queryString != null && !queryString.isEmpty()) {
            canonicalQueryString = createCanonicalQueryString(queryString);
        }

        String canonicalRequest = method + "\n" +
                uri + "\n" +
                canonicalQueryString + "\n" +
                canonicalHeaders + "\n" +
                signedHeaders + "\n" +
                payloadHash;

        // Step 4: Create string to sign
        String algorithm = AWSBedrockConstants.AWS4_ALGORITHM;
        // String region = "ap-southeast-2";
        String credentialScope = dateStamp + "/" + region + "/" + service + "/" +
                AWSBedrockConstants.AWS4_REQUEST;
        String stringToSign = algorithm + "\n" + amzDate + "\n" + credentialScope + "\n" + hash(canonicalRequest);

        // Step 5: Calculate signature
        byte[] signingKey = getSignatureKey(secretKey, dateStamp, region, service);
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

    private static String createCanonicalQueryString(String queryString) {
        return Arrays.stream(queryString.split("&"))
                .sorted(Comparator.comparing(param -> param.split("=", 2)[0]))
                .collect(Collectors.joining("&"));
    }

    public static Map<String, String> generateAWSSignatureUsingAssumeRole(
            String host, String method, String uri, String queryString, String payload,
            String accessKey, String secretKey, String region, String sessionToken,
            String roleArn, String roleRegion, String roleExternalId) throws Exception {

        if (logger.isDebugEnabled()) {
            logger.debug("AWSBedrockGuardrail: Generating temporary credential using AssumeRole");
        }

        // Set up STS endpoint and parameters
        String stsRegion = roleRegion != null && !roleRegion.isEmpty() ? roleRegion : "us-east-1";
        String stsHost = "sts." + stsRegion + ".amazonaws.com";
        String stsMethod = "GET";
        String stsUri = "/";

        // Create session name based on current date
        LocalDate now = LocalDate.now();
        String sessionName = String.format("%d%d%d", now.getYear(), now.getMonthValue(), now.getDayOfMonth());

        // Build query string for AssumeRole
        StringBuilder stsQueryBuilder = new StringBuilder();
        stsQueryBuilder.append("Action=AssumeRole");
        stsQueryBuilder.append("&Version=2011-06-15");
        stsQueryBuilder.append("&RoleArn=").append(URLEncoder.encode(roleArn, StandardCharsets.UTF_8));
        stsQueryBuilder.append("&RoleSessionName=").append(URLEncoder.encode(sessionName, StandardCharsets.UTF_8));
        if (roleExternalId != null && !roleExternalId.isEmpty()) {
            stsQueryBuilder.append("&ExternalId=").append(URLEncoder.encode(roleExternalId, StandardCharsets.UTF_8));
        }
        String stsQueryString = stsQueryBuilder.toString();

        // Generate signature for STS call
        Map<String, String> stsHeaders = generateAWSSignature(
                stsHost, stsMethod, "sts", stsUri, stsQueryString, "",
                accessKey, secretKey, stsRegion, sessionToken);

        // Call STS API to assume role
        URL url = new URL("https://" + stsHost + stsUri + "?" + stsQueryString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(stsMethod);

        // Add headers to the request
        for (Map.Entry<String, String> header : stsHeaders.entrySet()) {
            connection.setRequestProperty(header.getKey(), header.getValue());
        }

        // Get response
        int responseCode = connection.getResponseCode();
        if (responseCode != 200) {
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
            String errorLine;
            StringBuilder errorResponse = new StringBuilder();
            while ((errorLine = errorReader.readLine()) != null) {
                errorResponse.append(errorLine);
            }
            errorReader.close();

            logger.error("Failed to assume role. Response code: " + responseCode + ", Error: "
                    + errorResponse);
            throw new Exception("Failed to assume role: " + responseCode);
        }
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String line;
        StringBuilder response = new StringBuilder();
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();

        // Parse XML response
        String xmlResponse = response.toString();
        String tempAccessKey = extractXmlValue(xmlResponse, "AccessKeyId");
        String tempSecretKey = extractXmlValue(xmlResponse, "SecretAccessKey");
        String tempSessionToken = extractXmlValue(xmlResponse, "SessionToken");

        if (logger.isDebugEnabled()) {
            logger.debug("Successfully generated temporary credentials");
        }

        // Use temporary credentials to generate the final signature
        return generateAWSSignature(
                host, method, AWSBedrockConstants.BEDROCK_SERVICE, uri, queryString, payload, tempAccessKey,
                tempSecretKey, region, tempSessionToken);
    }

    // Helper method to extract values from XML
    private static String extractXmlValue(String xml, String tagName) {
        Pattern pattern = Pattern.compile("<" + tagName + ">(.*?)</" + tagName + ">");
        Matcher matcher = pattern.matcher(xml);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    // Helper method for SHA-256 hashing
    public static String hash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(digest);
    }

    // Helper method to get signature key
    public static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = (AWSBedrockConstants.AWS4 + key).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmacSHA256(dateStamp, kSecret);
        byte[] kRegion = hmacSHA256(regionName, kDate);
        byte[] kService = hmacSHA256(serviceName, kRegion);
        return hmacSHA256(AWSBedrockConstants.AWS4_REQUEST, kService);
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
