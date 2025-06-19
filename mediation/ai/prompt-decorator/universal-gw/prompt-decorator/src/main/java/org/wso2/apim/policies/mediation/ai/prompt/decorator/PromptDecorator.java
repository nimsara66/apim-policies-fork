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

package org.wso2.apim.policies.mediation.ai.prompt.decorator;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.TypeRef;
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

import java.util.ArrayList;
import java.util.List;

/**
 * PromptDecorator mediator.
 * <p>
 * A mediator that decorates specific parts of a JSON payload by either prepending or appending
 * content at a specified JSONPath location.
 * <p>
 * Supports modifying string fields or array fields based on the provided configuration.
 * Designed for use cases such as enhancing AI prompts or modifying request/response payloads dynamically.
 */
public class PromptDecorator extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(PromptDecorator.class);

    private String name;
    private String promptDecoratorConfig;
    private boolean append = false;
    private String jsonPath;
    private PromptDecoratorConstants.DecorationType type;
    private String decoration;

    /**
     * Initializes the PromptDecorator mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing PromptDecorator.");
        }
    }

    /**
     * Destroys the PromptTemplate mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
    }

    /**
     * Executes the PromptDecorator mediation logic.
     * <p>
     * Locates the target JSON field using JSONPath and applies the configured decoration.
     *
     * @param messageContext The message context containing the JSON payload.
     * @return {@code true} to continue mediation flow.
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Mediating message context with prompt decorator.");
        }

        try {
            findAndTransformPayload(messageContext);
        } catch (Exception e) {
            logger.error("Error during mediation of message context", e);

            messageContext.setProperty(SynapseConstants.ERROR_CODE,
                    PromptDecoratorConstants.APIM_INTERNAL_EXCEPTION_CODE);
            messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                    "Error occurred during PromptDecorator mediation");
            Mediator faultMediator = messageContext.getFaultSequence();
            faultMediator.mediate(messageContext);

            return false; // Stop further processing
        }

        return true;
    }

    /**
     * Locates the payload field using JSONPath and decorates it based on the configured settings.
     * <p>
     * Supports both string and array decorations. Updates the payload within the message context.
     *
     * @param messageContext The message context containing the JSON payload.
     * @throws AxisFault If an error occurs while modifying the payload.
     */
    private void findAndTransformPayload(MessageContext messageContext) throws AxisFault {
        if (logger.isDebugEnabled()) {
            logger.debug( name + " decorating JSON payload.");
        }

        String jsonContent = extractJsonContent(messageContext);
        if (jsonContent == null || jsonContent.isEmpty()) {
            return;
        }

        // Parse using JsonPath
        DocumentContext documentContext = JsonPath.parse(jsonContent);

        if (PromptDecoratorConstants.DecorationType.STRING.equals(type)) {
            // Read the existing string at the path
            String existingValue = documentContext.read(jsonPath, String.class);

            String updatedValue = !append
                    ? decoration + " " + existingValue
                    : existingValue + " " + decoration;

            // Set the new value
            documentContext.set(jsonPath, updatedValue);

        } else if (PromptDecoratorConstants.DecorationType.ARRAY.equals(type)) {
            // Read the existing array properly
            List<Object> existingArray = documentContext.read(jsonPath, new TypeRef<>() {
            });

            // Parse the decoration into a List<Object>
            List<Object> decorationList = JsonPath.parse(decoration).read("$", new TypeRef<>() {
            });

            List<Object> updatedArray = new ArrayList<>();

            if (!append) {
                updatedArray.addAll(decorationList);
                updatedArray.addAll(existingArray);
            } else {
                updatedArray.addAll(existingArray);
                updatedArray.addAll(decorationList);
            }

            // Set the updated array back
            documentContext.set(jsonPath, updatedArray);
        } else {
            logger.warn("Unknown decoration type: " + type);
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
     * This utility method converts the Axis2 message payload to a JSON string.
     *
     * @param messageContext The message context containing the JSON payload
     * @return The JSON payload as a string, or null if extraction fails
     */
    private String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getPromptDecoratorConfig() {

        return promptDecoratorConfig;
    }

    public void setPromptDecoratorConfig(String promptDecoratorConfig) {

        this.promptDecoratorConfig = promptDecoratorConfig;

        try {
            Gson gson = new Gson();
            JsonObject root = gson.fromJson(promptDecoratorConfig, JsonObject.class);

            if (root.has(PromptDecoratorConstants.DECORATION)
                    && root.get(PromptDecoratorConstants.DECORATION).isJsonArray()) {
                this.type = PromptDecoratorConstants.DecorationType.ARRAY;
                this.decoration = root.getAsJsonArray(PromptDecoratorConstants.DECORATION).toString();
            } else if (root.has(PromptDecoratorConstants.DECORATION)
                    && root.get(PromptDecoratorConstants.DECORATION).isJsonPrimitive()
                    && root.get(PromptDecoratorConstants.DECORATION).getAsJsonPrimitive().isString()) {
                this.type = PromptDecoratorConstants.DecorationType.STRING;
                this.decoration = root.get(PromptDecoratorConstants.DECORATION).getAsString();
            } else {
                throw new IllegalArgumentException(
                        "Invalid prompt template format: expected 'decoration' as array or string.");
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid prompt template provided: " + promptDecoratorConfig, e);
        }
    }

    public boolean isAppend() {

        return append;
    }

    public void setAppend(boolean append) {

        this.append = append;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }
}
