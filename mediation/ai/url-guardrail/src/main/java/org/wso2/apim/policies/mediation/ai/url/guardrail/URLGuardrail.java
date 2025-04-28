package org.wso2.apim.policies.mediation.ai.url.guardrail;

import com.jayway.jsonpath.JsonPath;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Regex Guardrail mediator for WSO2 API Gateway.
 *
 * This mediator provides content filtering capabilities for API payloads using regular expression patterns.
 * It intercepts API requests or responses, validates the JSON content against configured regex patterns,
 * and can block requests that match (or optionally don't match) the specified patterns.
 *
 * Key features:
 * - Flexible pattern matching - Apply regex patterns to entire JSON payloads or specific fields
 * - JsonPath support - Target validation to specific parts of JSON payloads using JsonPath expressions
 * - Invertible logic - Block content that matches OR doesn't match patterns
 * - Custom error responses - Return detailed assessment information when content is blocked
 *
 * When content violates the guardrail settings, the mediator triggers a fault sequence with
 * appropriate error details and blocks further processing of the request/ response.
 */
public class URLGuardrail extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(URLGuardrail.class);

    private String jsonPath = "";
    private boolean onlyDNS = false;

    /**
     * Initializes the URLGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("URLGuardrail: Initialized.");
        }
    }

    /**
     * Destroys the URLGuardrail mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Executing URLGuardrail mediation");
        }

        try {
            boolean validationResult = validatePayload(messageContext);

            if (!validationResult) {
                // Set error properties in message context
                messageContext.setProperty(SynapseConstants.ERROR_CODE,
                        URLGuardrailConstants.JSON_SCHEMA_GUARDRAIL_ERROR_CODE);
                messageContext.setProperty(URLGuardrailConstants.ERROR_TYPE, "Guardrail Blocked");
                messageContext.setProperty(URLGuardrailConstants.CUSTOM_HTTP_SC,
                        URLGuardrailConstants.JSON_SCHEMA_GUARDRAIL_ERROR_CODE);

                // Build assessment details
                String assessmentObject = buildAssessmentObject();
                messageContext.setProperty(SynapseConstants.ERROR_MESSAGE, assessmentObject);

                if (logger.isDebugEnabled()) {
                    logger.debug("Initiating JSONSchemaGuardrail fault sequence");
                }

                Mediator faultMediator = messageContext.getSequence(URLGuardrailConstants.FAULT_SEQUENCE_KEY);
                faultMediator.mediate(messageContext);
                return false; // Stop further processing
            }
        } catch (Exception e) {
            logger.error("Error during JSONSchemaGuardrail mediation", e);
        }

        return true;
    }

    private boolean validatePayload(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Validating URLGuardrail payload");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return false;
        }

        // If no JSON path is specified, apply regex to the entire JSON content
        if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
            return validateJsonAgainstURL(jsonContent);
        }

        // Check if any extracted value by json path matches the regex pattern
        return validateJsonAgainstURL(JsonPath.read(jsonContent, this.jsonPath).toString());
    }

    /**
     * Validates URLs found in a JSON string, either via DNS or full HTTP checks.
     *
     * @param input JSON string to validate
     * @return true if all validations pass, false otherwise
     */
    private boolean validateJsonAgainstURL(String input) {
        if (logger.isDebugEnabled()) {
            logger.debug("URLGuardrail validating content URLs");
        }

        List<String> urls = extractUrls(input);
        if (urls.isEmpty()) return true;

        List<CompletableFuture<Boolean>> futures = urls.stream()
                .map(url -> CompletableFuture.supplyAsync(() -> onlyDNS ? checkDNS(url) : checkUrl(url)))
                .collect(Collectors.toList());

        // Wait for all tasks to complete
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        // Aggregate results
        return futures.stream().map(CompletableFuture::join).allMatch(Boolean::booleanValue);
    }

    /**
     * Extracts all URLs from the input string using a simple regex.
     *
     * @param input input string containing potential URLs
     * @return list of extracted URLs
     */
    private List<String> extractUrls(String input) {
        Pattern urlPattern = Pattern.compile("https?://[^\\s,\"'{}\\[\\]]+");
        Matcher matcher = urlPattern.matcher(input);

        List<String> urls = new ArrayList<>();
        while (matcher.find()) {
            urls.add(matcher.group());
        }
        return urls;
    }

    private boolean checkUrl(String target) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL(target);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setRequestProperty("User-Agent", "URLValidator/1.0");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            connection.connect();

            int responseCode = connection.getResponseCode();
            return responseCode >= 200 && responseCode < 400;
        } catch (IOException e) {
            return false;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private boolean checkDNS(String target) {
        try {
            URL url = new URL(target);
            String host = url.getHost();

            String dnsUrl = "https://1.1.1.1/dns-query?name=" + host;
            HttpURLConnection connection = (HttpURLConnection) new URL(dnsUrl).openConnection();
            connection.setRequestProperty("Accept", "application/dns-json");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);

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
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    /**
     * Builds a JSON object containing assessment details from the guardrail response.
     *
     * @return A JSON object with assessment details
     */
    private String buildAssessmentObject() {
        if (logger.isDebugEnabled()) {
            logger.debug("Regex Guardrail assessment creation");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put("action", "GUARDRAIL_INTERVENED");
        assessmentObject.put("actionReason", "Guardrail blocked.");
        assessmentObject.put("assessments", "Violation of url validity detected.");
        return assessmentObject.toString();
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public boolean isOnlyDNS() {

        return onlyDNS;
    }

    public void setOnlyDNS(boolean onlyDNS) {

        this.onlyDNS = onlyDNS;
    }
}
