package org.wso2.apim.policies.mediation.ai.prompt.decorator;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.TypeRef;
import org.apache.axis2.AxisFault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

import java.lang.reflect.Type;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
public class PromptDecorator extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(PromptDecorator.class);

    private String promptDecoratorConfig;
    private boolean prepend = true;
    private String jsonPath;
    private PromptDecoratorConstants.DecorationType type;
    private String decoration;

    /**
     * Initializes the RegexGuardrail mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("PromptDecorator: Initialized.");
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
            logger.debug("Executing PromptDecorator mediation");
        }

        try {
            findAndTransformPayload(messageContext);
        } catch (Exception e) {
            logger.error("Error during PromptDecorator mediation", e);
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

        // Parse using JsonPath
        DocumentContext documentContext = JsonPath.parse(jsonContent);

        if (PromptDecoratorConstants.DecorationType.STRING.equals(this.type)) {
            // Read the existing string at the path
            String existingValue = documentContext.read(this.jsonPath, String.class);

            String updatedValue = this.prepend
                    ? this.decoration + " " + existingValue
                    : existingValue + " " + this.decoration;

            // Set the new value
            documentContext.set(this.jsonPath, updatedValue);

        } else if (PromptDecoratorConstants.DecorationType.ARRAY.equals(this.type)) {
            // Read the existing array properly
            List<Object> existingArray = documentContext.read(this.jsonPath, new TypeRef<>() {
            });

            // Parse the decoration into a List<Object>
            List<Object> decorationList = JsonPath.parse(this.decoration).read("$", new TypeRef<>() {
            });

            List<Object> updatedArray = new ArrayList<>();

            if (this.prepend) {
                updatedArray.addAll(decorationList);
                updatedArray.addAll(existingArray);
            } else {
                updatedArray.addAll(existingArray);
                updatedArray.addAll(decorationList);
            }

            // Set the updated array back
            documentContext.set(this.jsonPath, updatedArray);
        } else {
            logger.warn("Unknown type for decoration: " + this.type);
        }

        // Update the modified JSON
        jsonContent = documentContext.jsonString();


        // Update the payload
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        JsonUtil.getNewJsonPayload(axis2MC, jsonContent,
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

    public String getPromptDecoratorConfig() {

        return promptDecoratorConfig;
    }

    public void setPromptDecoratorConfig(String promptDecoratorConfig) {

        this.promptDecoratorConfig = promptDecoratorConfig;

        try {
            Gson gson = new Gson();
            JsonObject root = gson.fromJson(promptDecoratorConfig, JsonObject.class);

            if (root.has("decoration") && root.get("decoration").isJsonArray()) {
                this.type = PromptDecoratorConstants.DecorationType.ARRAY;
                this.decoration = root.getAsJsonArray("decoration").toString();
            } else if (root.has("decoration") && root.get("decoration").isJsonPrimitive()
                    && root.get("decoration").getAsJsonPrimitive().isString()) {
                this.type = PromptDecoratorConstants.DecorationType.STRING;
                this.decoration = root.getAsString();
            } else {
                logger.error("Invalid prompt template provided: " + promptDecoratorConfig);
            }
        } catch (Exception e) {
            logger.error("Invalid prompt template provided: " + promptDecoratorConfig, e);
        }
    }

    public boolean isPrepend() {

        return prepend;
    }

    public void setPrepend(boolean prepend) {

        this.prepend = prepend;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }
}
