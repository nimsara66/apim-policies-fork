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

package org.wso2.apim.policies.mediation.ai.prompt.template;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PromptTemplate mediator.
 * <p>
 * <p>
 * The PromptTemplate mediator scans JSON payloads for template references in the format
 * {@code template://<template-name>?<param1>=<value1>&<param2>=<value2>} and replaces them
 * with predefined templates where parameter placeholders are substituted with provided values.
 * This is particularly useful for standardizing prompts across different API calls, especially
 * when working with large language models or AI services.
 * <p>
 * Template references in the payload are processed using regex pattern matching and URI parsing.
 * Each template placeholder in the format {@code [[parameter-name]]} is replaced with the
 * corresponding parameter value from the template URI query string.
 * <p>
 * Configuration is provided through a JSON array of template objects, each containing a name and
 * prompt definition:
 * <pre>
 * [
 *   {
 *     "name": "translate",
 *     "prompt": "Translate the following text from [[from]] to [[to]]: [[text]]"
 *   },
 *   {
 *     "name": "summarize",
 *     "prompt": "Summarize the following content in [[length]] words: [[content]]"
 *   }
 * ]
 * </pre>
 * <p>
 * Example usage in a payload:
 * <pre>
 * {
 *   "messages": [
 *     {
 *       "role": "user",
 *       "content": "template://translate?from=english&to=spanish&text=Hello world"
 *     }
 *   ]
 * }
 * </pre>
 * <p>
 * The mediator would transform this to:
 * <pre>
 * {
 *   "messages": [
 *     {
 *       "role": "user",
 *       "content": "Translate the following text from english to spanish: Hello world"
 *     }
 *   ]
 * }
 * </pre>
 */
public class PromptTemplate extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(PromptTemplate.class);

    private String name;
    private String promptTemplateConfig;
    private final Map<String, String> promptTemplates = new HashMap<>();

    /**
     * Initializes the PromptTemplate mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing PromptTemplate.");
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
     * Mediates the message context by transforming the payload using prompt templates.
     * <p>
     * This method looks for placeholders in the JSON payload that match the predefined templates, and replaces
     * them with the appropriate values. It logs the mediation progress and handles any exceptions that occur during
     * the mediation process.
     *
     * @param messageContext The message context containing the JSON payload to be mediated.
     * @return {@code true} to continue the mediation process.
     */
    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("Mediating message context with prompt templates.");
        }

        try {
            findAndTransformPayload(messageContext);
        } catch (Exception e) {
            logger.error("Error during mediation of message context", e);
        }

        return true;
    }

    /**
     * Finds and transforms the payload in the message context by resolving template placeholders.
     * <p>
     * This method searches the JSON content for template placeholders in the form of
     * {@code template://<template-name>?<params>} and replaces them with the corresponding template values.
     *
     * @param messageContext The message context containing the JSON payload.
     * @throws AxisFault If an error occurs while modifying the payload.
     */
    private void findAndTransformPayload(MessageContext messageContext) throws AxisFault {
        if (logger.isDebugEnabled()) {
            logger.debug(this.name + "applying prompt templates.");
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
     * Extracts the JSON content from the provided message context.
     * <p>
     * This method retrieves the JSON payload from the message context and returns it as a string.
     *
     * @param messageContext The message context containing the JSON payload.
     * @return The extracted JSON content as a string, or {@code null} if no JSON content is found.
     */
    public static String extractJsonContent(MessageContext messageContext) {
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
                String name = item.get(PromptTemplateConstants.PROMPT_TEMPLATE_NAME);
                String prompt = item.get(PromptTemplateConstants.PROMPT_TEMPLATE_PROMPT);
                promptTemplates.put(name, prompt);
            }
        } catch (Exception e) {
            logger.error("Invalid prompt template provided: " + promptTemplateConfig, e);
        }
    }
}
