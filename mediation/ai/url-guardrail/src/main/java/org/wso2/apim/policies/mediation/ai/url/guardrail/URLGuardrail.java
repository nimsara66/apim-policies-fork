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

package org.wso2.apim.policies.mediation.ai.url.guardrail;

import com.jayway.jsonpath.JsonPath;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * URL Guardrail mediator.
 * <p>
 * A Synapse mediator that performs URL validation on payloads by extracting URLs from JSON content
 * and validating them either via DNS resolution or HTTP connectivity checks. This guardrail ensures
 * that external references in payloads point to reachable or resolvable hosts, enhancing input safety
 * and reducing the risk of external threats.
 * <p>
 * The validator supports JSONPath expressions to isolate specific sections of the payload for
 * URL extraction. If no JSONPath is provided, the entire payload is scanned for URL patterns.
 * Based on configuration, the guardrail performs lightweight DNS lookups or full HTTP HEAD requests.
 * <p>
 * If validation fails, the mediator halts message processing, sets error details in the message context,
 * and invokes a configured fault sequence. The response includes a structured assessment object with
 * metadata about the guardrail intervention.
 */
public class URLGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(URLGuardrail.class);

    private String name;
    private String jsonPath = "";
    private int timeout = 5000;
    private boolean onlyDNS = false;
    private boolean hideAssessment = true;

    /**
     * Initializes the URLGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing Guardrail");
        }
    }

    /**
     * Destroys the URLGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    /**
     * Entry point for mediation. Performs URL validation against the incoming JSON payload.
     *
     * @param messageContext the Synapse message context
     * @return true if validation passed and processing should continue; false if blocked
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Starting mediation.");
        }

        try {
            List<String> invalidUrls = validatePayload(messageContext);

            if (!invalidUrls.isEmpty()) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        URLGuardrailConstants.GUARDRAIL_APIM_EXCEPTION_CODE);
                messageContext.setProperty(URLGuardrailConstants.ERROR_TYPE, URLGuardrailConstants.URL_GUARDRAIL);
                messageContext.setProperty(URLGuardrailConstants.CUSTOM_HTTP_SC,
                        URLGuardrailConstants.GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject(invalidUrls, messageContext.isResponse());
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);
                logger.info("Validation failed - triggering fault sequence.");

                Mediator faultMediator = messageContext.getSequence(URLGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Error during mediation", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE, URLGuardrailConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, "Error occurred during URLGuardrail mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);
            return false; // Stop further processing
        }

        return true;
    }

    /**
     * Validates the payload by extracting JSON and scanning for URLs.
     *
     * @param messageContext the Synapse message context
     * @return a list of invalid URLs; an empty list if all are valid
     */
    private List<String> validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating payload.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return Collections.emptyList();
        }

        // If no JSON path is specified, apply validation to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return validateJsonAgainstURL(jsonContent);
        }

        return validateJsonAgainstURL(JsonPath.read(jsonContent, this.jsonPath).toString());
    }

    /**
     * Validates a given JSON string by extracting and checking all contained URLs.
     *
     * @param input the JSON or string content
     * @return a list of invalid URLs; an empty list if all are valid
     */
    private List<String> validateJsonAgainstURL(String input) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating extracted URLs.");
        }

        Set<String> urls = extractUrls(input);
        if (urls.isEmpty()) return Collections.emptyList();

        Map<String, CompletableFuture<Boolean>> futureMap = urls.stream()
                .collect(Collectors.toMap(
                        Function.identity(),
                        url -> CompletableFuture.supplyAsync(() -> onlyDNS ? checkDNS(url) : checkUrl(url))
                ));

        // Wait for all tasks to complete
        CompletableFuture.allOf(futureMap.values().toArray(new CompletableFuture[0])).join();

        return futureMap.entrySet().stream()
                .filter(entry -> !entry.getValue().join())
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());
    }

    /**
     * Extracts all URLs from the input string using a simple regex.
     *
     * @param input input string containing potential URLs
     * @return set of extracted URLs
     */
    private Set<String> extractUrls(String input) {
        Pattern urlPattern = Pattern.compile(URLGuardrailConstants.URL_REGEX);
        Matcher matcher = urlPattern.matcher(input);

        Set<String> urls = new LinkedHashSet<>();
        while (matcher.find()) {
            urls.add(matcher.group());
        }
        return urls;
    }

    /**
     * Checks if the URL is reachable via HTTP HEAD request.
     *
     * @param target URL to check
     * @return true if reachable, false otherwise
     */
    private boolean checkUrl(String target) {
        try (CloseableHttpClient client = HttpClients.custom().build()) {
            HttpHead request = new HttpHead(target);
            request.setProtocolVersion(HttpVersion.HTTP_1_1);
            request.setHeader("User-Agent", "URLValidator/1.0");

            RequestConfig config = RequestConfig.custom()
                    .setConnectTimeout(this.timeout)
                    .setSocketTimeout(this.timeout)
                    .build();
            request.setConfig(config);

            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            return statusCode >= 200 && statusCode < 400;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Checks if the URL resolves via DNS.
     *
     * @param target URL to check
     * @return true if DNS resolution is successful, false otherwise
     */
    private boolean checkDNS(String target) {
        try {
            URL url = new URL(target);
            String host = url.getHost();

            String dnsUrl = "https://1.1.1.1/dns-query?name=" + host;
            HttpURLConnection connection = (HttpURLConnection) new URL(dnsUrl).openConnection();
            connection.setRequestProperty("Accept", "application/dns-json");
            connection.setConnectTimeout(this.timeout);
            connection.setReadTimeout(this.timeout);

            InputStream inputStream = connection.getInputStream();
            String responseBody = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
            inputStream.close();

            // Parse JSON to check DNS status and answer
            JSONObject json = new JSONObject(responseBody);
            int status = json.getInt("Status");
            JSONArray answers = json.optJSONArray("Answer");

            return status == 0 && answers != null && answers.length() > 0;
        } catch (Exception e) {
            return false;
        }
    }


    /**
     * Extracts JSON content from the message context.
     * This utility method converts the Axis2 message payload to a JSON string.
     *
     * @param messageContext The message context containing the JSON payload
     * @return The JSON payload as a string, or null if extraction fails
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    /**
     * Builds a JSON object containing assessment details for guardrail responses.
     * This JSON includes information about why the guardrail intervened.
     *
     * @return A JSON string representing the assessment object
     */
    private String buildAssessmentObject(List<String> invalidUrls, boolean isResponse) {
        if (logger.isDebugEnabled()) {
            logger.debug("Building guardrail assessment object.");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(URLGuardrailConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(URLGuardrailConstants.INTERVENING_GUARDRAIL, this.getName());
        assessmentObject.put(URLGuardrailConstants.DIRECTION, isResponse? "RESPONSE" : "REQUEST");
        assessmentObject.put(URLGuardrailConstants.ASSESSMENT_REASON, "Violation of url validity detected.");

        if (!this.hideAssessment) {
            JSONObject assessmentDetails = new JSONObject();
            assessmentDetails.put("message", "One or more URLs in the payload failed validation.");
            assessmentDetails.put("invalidUrls", new JSONArray(invalidUrls));
            assessmentObject.put(URLGuardrailConstants.ASSESSMENTS, assessmentDetails);
        }

        return assessmentObject.toString();
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public int getTimeout() {

        return timeout;
    }

    public void setTimeout(int timeout) {

        this.timeout = timeout;
    }

    public boolean isOnlyDNS() {

        return onlyDNS;
    }

    public void setOnlyDNS(boolean onlyDNS) {

        this.onlyDNS = onlyDNS;
    }

    public boolean isHideAssessment() {

        return hideAssessment;
    }

    public void setHideAssessment(boolean hideAssessment) {

        this.hideAssessment = hideAssessment;
    }
}
