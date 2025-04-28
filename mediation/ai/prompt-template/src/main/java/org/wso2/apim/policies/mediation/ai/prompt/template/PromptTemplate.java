package org.wso2.apim.policies.mediation.ai.prompt.template;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.jayway.jsonpath.JsonPath;
import org.apache.axis2.AxisFault;
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
import org.json.JSONObject;

import java.lang.reflect.Type;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
public class PromptTemplate extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(PromptTemplate.class);

    private String promptTemplateConfig;
    private final Map<String, String> promptTemplates = new HashMap<>();

    /**
     * Initializes the RegexGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("PromptTemplate: Initialized.");
        }
    }

    /**
     * Destroys the PromptTemplate mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Executing PromptTemplate mediation");
        }

        try {
            findAndTransformPayload(messageContext);
        } catch (Exception e) {
            logger.error("Error during PromptTemplate mediation", e);
        }

        return true;
    }

    private void findAndTransformPayload(MessageContext messageContext) throws AxisFault {
        if (logger.isDebugEnabled()) {
            logger.debug("PromptTemplate transforming payload");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return;
        }

        String updatedJsonContent = jsonContent;

        // Regex to find template://<template-name>?<params>
        Pattern pattern = Pattern.compile(PromptTemplateConstants.PROMPT_TEMPLATE_REGEX);
        Matcher matcher = pattern.matcher(jsonContent);

        while (matcher.find()) {
            String matched = matcher.group(); // ex: template://translate?from=english&to=spanish

            try {
                // Parse the matched string as a URI
                URI uri = new URI(matched);
                String templateName = uri.getHost(); // translate
                String query = uri.getQuery(); // from=english&to=spanish

                if (promptTemplates.containsKey(templateName)) {
                    String template = promptTemplates.get(templateName);

                    // Parse query parameters
                    Map<String, String> params = new HashMap<>();
                    if (query != null) {
                        String[] pairs = query.split("&");
                        for (String pair : pairs) {
                            String[] keyValue = pair.split("=", 2);
                            if (keyValue.length == 2) {
                                String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                                String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                                params.put(key, value);
                            }
                        }
                    }

                    // Replace placeholders in template
                    String resolvedPrompt = template;
                    for (Map.Entry<String, String> entry : params.entrySet()) {
                        String placeholder = "[[" + entry.getKey() + "]]";
                        resolvedPrompt = resolvedPrompt.replace(placeholder, entry.getValue());
                    }

                    // Directly replace in updatedJsonContent
                    updatedJsonContent = updatedJsonContent.replace(matched, resolvedPrompt);
                } else {
                    logger.warn("No prompt template found for: " + templateName);
                }
            } catch (Exception e) {
                logger.error("Error while transforming template for match: " + matched, e);
            }
        }

        // Update the payload
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        JsonUtil.getNewJsonPayload(axis2MC, updatedJsonContent,
                true, true);
    }

    /**
     * Extracts JSON content from the message context.
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    public String getPromptTemplateConfig() {

        return promptTemplateConfig;
    }

    public void setPromptTemplateConfig(String promptTemplateConfig) {

        this.promptTemplateConfig = promptTemplateConfig;

        try {
            Gson gson = new Gson();
            Type listType = new TypeToken<List<Map<String, String>>>() {}.getType();
            List<Map<String, String>> templates = gson.fromJson(promptTemplateConfig, listType);

            for (Map<String, String> item : templates) {
                String name = item.get("name");
                String prompt = item.get("prompt");
                promptTemplates.put(name, prompt);
            }
        } catch (Exception e) {
            logger.error("Invalid prompt template provided: " + promptTemplateConfig, e);
        }
    }
}
