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

package org.wso2.apim.policies.mediation.ai.semantic.cache;

import com.jayway.jsonpath.JsonPath;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.commons.collections.map.MultiValueMap;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.ParseException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.SynapseLog;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.synapse.transport.nhttp.NhttpConstants;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.util.FixedByteArrayOutputStream;
import org.apache.synapse.util.MessageHelper;
import redis.clients.jedis.UnifiedJedis;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import javax.xml.stream.XMLStreamException;

/**
 * Regex Guardrail mediator.
 * <p>
 * A mediator that performs piiEntities-based validation on payloads according to specified patterns.
 * This guardrail can be configured with JSON path expressions to target specific parts of JSON payloads
 * and apply piiEntities pattern validation against them. The validation result can be inverted if needed.
 * <p>
 * When validation fails, the mediator triggers a fault sequence and enriches the message context
 * with appropriate error details.
 */
public class SemanticCache extends AbstractMediator implements ManagedLifecycle {
    private static final Log logger = LogFactory.getLog(SemanticCache.class);

    private String name;
    private String vectorIndex = UUID.randomUUID().toString();
    private double threshold = 0.8;
    private int timeout = 3600;
    private int ttl = 3600;
    private int embeddingDimensions = 1024;
    private String jsonPath = "";
    private String protocolType = SemanticCacheConstants.HTTP_PROTOCOL_TYPE;
    private String responseCodes = SemanticCacheConstants.ANY_RESPONSE_CODE;
    private String[] hTTPMethodsToCache = {SemanticCacheConstants.ALL};
    private int maxMessageSize = SemanticCacheConstants.DEFAULT_SIZE;
    private boolean cacheControlEnabled = SemanticCacheConstants.DEFAULT_ENABLE_CACHE_CONTROL;
    private boolean addAgeHeaderEnabled = SemanticCacheConstants.DEFAULT_ADD_AGE_HEADER;
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String SC_NOT_MODIFIED = "304";

    private VectorDBProvider vectorDBProvider;
    private EmbeddingProvider embeddingProvider;

    /**
     * Initializes the SemanticCache mediator.
     *
     * @param synapseEnvironment The Synapse environment instance.
     */
    @Override
    public void init(SynapseEnvironment synapseEnvironment) {
        if (logger.isDebugEnabled()) {
            logger.debug("SemanticCache: Initialized.");
        }

        UnifiedJedis jedis = new UnifiedJedis("redis://localhost:6379");
        this.vectorDBProvider = new RedisVectorDBProvider(jedis, this.ttl,
                this.embeddingDimensions, "L2", this.threshold);
        this.vectorDBProvider.createIndex(this.vectorIndex);

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(this.timeout)
                .setConnectionRequestTimeout(this.timeout)
                .setSocketTimeout(this.timeout)
                .build();

        CloseableHttpClient httpClient = HttpClients.custom()
                .setDefaultRequestConfig(requestConfig)
                .build();

        this.embeddingProvider = new MistralEmbeddingProvider(
                httpClient,
                "x2c1cKUy3PQxHZMUN2Gjvgpi1fjOVejg",
                "https://api.mistral.ai/v1/embeddings",
                "mistral-embed"
        );
    }

    /**
     * Destroys the SemanticCache mediator instance and releases any allocated resources.
     */
    @Override
    public void destroy() {
        // No specific resources to release
        System.out.println("SemanticCache: Destroyed.");
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        if (logger.isDebugEnabled()) {
            logger.debug("SemanticCache: Beginning payload validation.");
        }

        SynapseLog synLog = getLog(messageContext);
        if (synLog.isTraceOrDebugEnabled()) {
            synLog.traceOrDebug("Start : SemanticCache mediator");

            if (synLog.isTraceTraceEnabled()) {
                synLog.traceTrace("Message : " + messageContext.getEnvelope());
            }
        }

        boolean result = true;
        try {
            if (messageContext.isResponse()) {
                processResponseMessage(messageContext, synLog);
            } else {
                result = processRequestMessage(messageContext, synLog);
            }
        } catch (Exception e) {
            logger.error("SemanticCache: Exception occurred during mediation.", e);
        }

        return result;
    }

    private boolean processRequestMessage(MessageContext messageContext, SynapseLog synLog)
            throws IOException {
        org.apache.axis2.context.MessageContext msgCtx =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();

        // Extract content from body and get embeddings
        String contentToEmbed = extractContent(msgCtx);
        if (contentToEmbed == null) {
            // Proceed without caching
            logger.error("SemanticCache: No content found in the message context.");
            return true;
        }

        float[] embeddings = this.embeddingProvider.getEmbedding(contentToEmbed);
        // Check if cache hit
        CachableResponse cachedResponse = this.vectorDBProvider.retrieve(embeddings);

        if (cachedResponse != null
                && (cachedResponse.getResponsePayload() != null || cachedResponse.getResponseEnvelope() != null)) {
            // get the response from the cache and attach to the context and change the
            // direction of the message
            if (synLog.isTraceOrDebugEnabled()) {
                synLog.traceOrDebug("Cache-hit for message ID : " + messageContext.getMessageID());
            }
            //Validate the response based on max-age and no-cache headers.
            if (SemanticCacheConstants.HTTP_PROTOCOL_TYPE.equals(getProtocolType())
                    && cachedResponse.isCacheControlEnabled()) {
                return true;
            }
            // mark as a response and replace envelope from cache
            messageContext.setResponse(true);
            replaceEnvelopeWithCachedResponse(messageContext, synLog, msgCtx, cachedResponse);
            return false;
        }
        messageContext.setProperty(SemanticCacheConstants.REQUEST_EMBEDDINGS, embeddings);
        return true;
    }

    private String extractContent(org.apache.axis2.context.MessageContext msgCtx) {
        if (logger.isDebugEnabled()) {
            logger.debug("SemanticCache: Extracting content from message context.");
        }

        // Case 1: JSON Payload
        if (JsonUtil.hasAJsonPayload(msgCtx)) {
            String jsonContent = JsonUtil.jsonPayloadToString(msgCtx);

            if (this.jsonPath == null || this.jsonPath.trim().isEmpty()) {
                return jsonContent;
            }

            try {
                String extracted = JsonPath.read(jsonContent, this.jsonPath).toString();
                return extracted.replaceAll("^\"|\"$", "").trim();
            } catch (Exception e) {
                logger.warn("SemanticCache: Failed to extract content using jsonPath: " + this.jsonPath, e);
            }
        } else {
            // Case 2: SOAP/XML Envelope
            try {
                SOAPEnvelope envelope = msgCtx.getEnvelope();
                if (envelope != null) {
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    envelope.serialize(byteArrayOutputStream);
                    return byteArrayOutputStream.toString(StandardCharsets.UTF_8).trim();
                }
            } catch (Exception e) {
                logger.error("SemanticCache: Failed to extract SOAP envelope", e);
            }
        }

        return null;
    }

    private void replaceEnvelopeWithCachedResponse(MessageContext synCtx, SynapseLog synLog,
                                                   org.apache.axis2.context.MessageContext msgCtx,
                                                   CachableResponse cachedResponse) {
        Map<String, Object> headerProperties;
        try {
            if (cachedResponse.isJson()) {
                byte[] payload = cachedResponse.getResponsePayload();
                OMElement response = JsonUtil.getNewJsonPayload(msgCtx, payload, 0,
                        payload.length, false, false);
                if (msgCtx.getEnvelope().getBody().getFirstElement() != null) {
                    msgCtx.getEnvelope().getBody().getFirstElement().detach();
                }
                msgCtx.getEnvelope().getBody().addChild(response);

            } else {
                msgCtx.setEnvelope(MessageHelper.cloneSOAPEnvelope(cachedResponse.getResponseEnvelope()));
            }
        } catch (AxisFault e) {
            handleException("Error creating response OM from cache : " + this.name, synCtx);
        }
        if (SemanticCacheConstants.HTTP_PROTOCOL_TYPE.equals(getProtocolType())) {
            if (cachedResponse.getStatusCode() != null) {
                msgCtx.setProperty(NhttpConstants.HTTP_SC,
                        Integer.parseInt(cachedResponse.getStatusCode()));
            }
            if (cachedResponse.getStatusReason() != null) {
                msgCtx.setProperty(PassThroughConstants.HTTP_SC_DESC, cachedResponse.getStatusReason());
            }
            //Set Age header to the cached response.
            if (cachedResponse.isAddAgeHeaderEnabled()) {
                this.setAgeHeader(cachedResponse, msgCtx);
            }
        }
        if (msgCtx.isDoingREST()) {

            msgCtx.removeProperty(PassThroughConstants.NO_ENTITY_BODY);
            msgCtx.removeProperty(Constants.Configuration.CONTENT_TYPE);
        }
        if ((headerProperties = cachedResponse.getHeaderProperties()) != null) {
            Map<String, Object> clonedMap = new HashMap<>(headerProperties);
            msgCtx.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, clonedMap);
            msgCtx.setProperty(Constants.Configuration.MESSAGE_TYPE,
                    clonedMap.get(Constants.Configuration.MESSAGE_TYPE));
            msgCtx.setProperty(Constants.Configuration.CONTENT_TYPE,
                    headerProperties.get(CONTENT_TYPE));
        }

        if (synLog.isTraceOrDebugEnabled()) {
            synLog.traceOrDebug("Request message " + synCtx.getMessageID() +
                    " was served from the cache");
        }
        // send the response back if there is not onCacheHit is specified
        synCtx.setTo(null);
        Axis2Sender.sendBack(synCtx);
    }

    public void setAgeHeader(CachableResponse cachedResponse,
                                    org.apache.axis2.context.MessageContext msgCtx) {
        Map excessHeaders = new MultiValueMap();
        long responseCachedTime = cachedResponse.getResponseFetchedTime();
        long age = Math.abs((responseCachedTime - System.currentTimeMillis()) / 1000);
        excessHeaders.put(HttpHeaders.AGE, String.valueOf(age));

        msgCtx.setProperty(NhttpConstants.EXCESS_TRANSPORT_HEADERS, excessHeaders);
    }

    private void processResponseMessage(MessageContext messageContext, SynapseLog synLog) throws java.text.ParseException {
        org.apache.axis2.context.MessageContext msgCtx = ((Axis2MessageContext) messageContext).getAxis2MessageContext();

        float[] embeddings = (float[]) messageContext.getProperty(SemanticCacheConstants.REQUEST_EMBEDDINGS);

        if (embeddings != null) {
            // Init cache response
            CachableResponse response = new CachableResponse();
            String httpMethod = (String) msgCtx.getProperty(Constants.Configuration.HTTP_METHOD);
            response.setHttpMethod(httpMethod);
            response.setProtocolType(protocolType);
            response.setResponseCodePattern(responseCodes);
            response.setHTTPMethodsToCache(hTTPMethodsToCache); // TODO: Ask arshardh if we need this
            response.setMaxMessageSize(maxMessageSize);
            response.setCacheControlEnabled(cacheControlEnabled);
            response.setAddAgeHeaderEnabled(addAgeHeaderEnabled);

            boolean toCache = true;
            if (SemanticCacheConstants.HTTP_PROTOCOL_TYPE.equals(response.getProtocolType())) {
                Object httpStatus = msgCtx.getProperty(NhttpConstants.HTTP_SC);
                String statusCode = null;
                //Honor no-store header if cacheControlEnabled.
                // If "no-store" header presents in the response, returned response can not be cached.
                if (response.isCacheControlEnabled() && this.isNoStore(msgCtx)) {
                    response.clean();
                    return;
                }
                //Need to check the data type of HTTP_SC to avoid classcast exceptions.
                if (httpStatus instanceof String) {
                    statusCode = ((String) httpStatus).trim();
                } else if (httpStatus != null) {
                    statusCode = String.valueOf(httpStatus);
                }

                if (statusCode != null) {
                    //If status code is SC_NOT_MODIFIED then return the cached response.
                    // TODO: What is happening here?
                    if (statusCode.equals(SC_NOT_MODIFIED)) {
                        replaceEnvelopeWithCachedResponse(messageContext, synLog, msgCtx, response);
                        return;
                    }
                    // Now create matcher object.
                    Matcher m = response.getResponseCodePattern().matcher(statusCode);
                    if (m.matches()) {
                        response.setStatusCode(statusCode);
                        response.setStatusReason((String) msgCtx.getProperty(PassThroughConstants.HTTP_SC_DESC));
                    } else {
                        toCache = false;
                    }
                }

                if (toCache) {
                    toCache = false;
                    for (String method : response.getHTTPMethodsToCache()) {
                        if (method.equals("*") || method.equals(httpMethod)) {
                            toCache = true;
                            break;
                        }
                    }
                }
            }
            if (toCache) {
                if (JsonUtil.hasAJsonPayload(msgCtx)) {
                    byte[] responsePayload = JsonUtil.jsonPayloadToByteArray(msgCtx);
                    if (response.getMaxMessageSize() > -1 &&
                            responsePayload.length > response.getMaxMessageSize()) {
                        synLog.traceOrDebug(
                                "Message size exceeds the upper bound for caching, request will not be cached");
                        return;
                    }
                    response.setResponsePayload(responsePayload);
                    response.setResponseEnvelope(null);
                    response.setJson(true);
                } else {
                    // TODO: This implementation is incomplete
                    SOAPEnvelope clonedEnvelope = MessageHelper.cloneSOAPEnvelope(messageContext.getEnvelope());
                    if (response.getMaxMessageSize() > -1) {
                        FixedByteArrayOutputStream fbaos = new FixedByteArrayOutputStream(
                                response.getMaxMessageSize());
                        try {
                            clonedEnvelope.serialize(fbaos);
                        } catch (XMLStreamException e) {
                            handleException("Error in checking the message size", e, messageContext);
                        } catch (SynapseException syne) {
                            synLog.traceOrDebug(
                                    "Message size exceeds the upper bound for caching, request will not be cached");
                            return;
                        } finally {
                            try {
                                fbaos.close();
                            } catch (IOException e) {
                                handleException("Error occurred while closing the FixedByteArrayOutputStream ", e,
                                        messageContext);
                            }
                        }
                    }

                    response.setResponsePayload(null);
                    response.setResponseEnvelope(clonedEnvelope);
                    response.setJson(false);

                }

                if (synLog.isTraceOrDebugEnabled()) {
                    synLog.traceOrDebug(
                            "Storing the response for the message with ID : " + messageContext.getMessageID()
                                    + " " + "with request hash ID : " + response.getRequestHash() + " in the cache");
                }

                Map<String, String> headers =
                        (Map<String, String>) msgCtx.getProperty(
                                org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
                String messageType = (String) msgCtx.getProperty(Constants.Configuration.MESSAGE_TYPE);
                Map<String, Object> headerProperties = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

                //Store the response fetched time.
                if (response.isCacheControlEnabled() || response.isAddAgeHeaderEnabled()) {
                    try {
                        this.setResponseCachedTime(headers, response);
                    } catch (ParseException e) {
                        synLog.auditWarn("Error occurred while parsing the date." + e.getMessage());
                    }
                }
                //Individually copying All TRANSPORT_HEADERS to headerProperties Map instead putting whole
                //TRANSPORT_HEADERS map as single Key/Value pair to fix hazelcast serialization issue.
                headerProperties.putAll(headers);
                headerProperties.put(Constants.Configuration.MESSAGE_TYPE, messageType);
                headerProperties.put(SemanticCacheConstants.CACHE_KEY, response.getRequestHash());
                response.setHeaderProperties(headerProperties);
                msgCtx.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headerProperties);

                // Store cachedResponse in the vectorDB
                try {
                    this.vectorDBProvider.store(embeddings, response);
                } catch (IOException e) {
                    logger.error("Failed to store embeddings and response in vectorDBProvider", e);
                }
            } else {
                response.clean();
            }
        } else {
            synLog.auditWarn("A response message without a valid mapping to the " +
                    "request hash found. Unable to store the response in cache");
        }
    }

    public void setResponseCachedTime(Map<String, String> headers, CachableResponse response) throws
            ParseException, java.text.ParseException {
        long responseFetchedTime;
        String dateHeaderValue;
        if (headers != null && (dateHeaderValue = headers.get(HttpHeaders.DATE)) != null) {
            SimpleDateFormat format = new SimpleDateFormat(SemanticCacheConstants.DATE_PATTERN);
            Date d = format.parse(dateHeaderValue);
            responseFetchedTime = d.getTime();
        } else {
            responseFetchedTime = System.currentTimeMillis();
        }
        response.setResponseFetchedTime(responseFetchedTime);
    }

    public boolean isNoStore(org.apache.axis2.context.MessageContext msgCtx) {
        ConcurrentHashMap<String, Object> headerProperties = new ConcurrentHashMap<>();
        Map<String, String> headers = (Map<String, String>) msgCtx.getProperty(
                org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        String cacheControlHeaderValue = null;

        //Copying All TRANSPORT_HEADERS to headerProperties Map.
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            headerProperties.put(entry.getKey(), entry.getValue());
        }
        if (headerProperties.get(HttpHeaders.CACHE_CONTROL) != null) {
            cacheControlHeaderValue = String.valueOf(headerProperties.get(HttpHeaders.CACHE_CONTROL));
        }

        return StringUtils.isNotEmpty(cacheControlHeaderValue)
                && cacheControlHeaderValue.contains(SemanticCacheConstants.NO_STORE_STRING);
    }

    public String getName() {

        return name;
    }

    public void setName(String name) {

        this.name = name;
    }

    public String getVectorIndex() {

        return vectorIndex;
    }

    public void setVectorIndex(String vectorIndex) {

        this.vectorIndex = vectorIndex;
    }

    public double getThreshold() {

        return threshold;
    }

    public void setThreshold(double threshold) {

        this.threshold = threshold;
    }

    public int getTimeout() {

        return timeout;
    }

    public void setTimeout(int timeout) {

        this.timeout = timeout;
    }

    public int getTtl() {

        return ttl;
    }

    public void setTtl(int ttl) {

        this.ttl = ttl;
    }

    public int getEmbeddingDimensions() {

        return embeddingDimensions;
    }

    public void setEmbeddingDimensions(int embeddingDimensions) {

        this.embeddingDimensions = embeddingDimensions;
    }

    public String getJsonPath() {

        return jsonPath;
    }

    public void setJsonPath(String jsonPath) {

        this.jsonPath = jsonPath;
    }

    public void setProtocolType(String protocolType) {

        this.protocolType = protocolType;
    }

    public String getProtocolType() {
        return protocolType;
    }

    public String getResponseCodes() {

        return responseCodes;
    }

    public void setResponseCodes(String responseCodes) {

        this.responseCodes = responseCodes;
    }

    public String[] gethTTPMethodsToCache() {

        return hTTPMethodsToCache;
    }

    public void sethTTPMethodsToCache(String[] hTTPMethodsToCache) {

        this.hTTPMethodsToCache = hTTPMethodsToCache;
    }

    public int getMaxMessageSize() {

        return maxMessageSize;
    }

    public void setMaxMessageSize(int maxMessageSize) {

        this.maxMessageSize = maxMessageSize;
    }

    public boolean isCacheControlEnabled() {

        return cacheControlEnabled;
    }

    public void setCacheControlEnabled(boolean cacheControlEnabled) {

        this.cacheControlEnabled = cacheControlEnabled;
    }

    public boolean isAddAgeHeaderEnabled() {

        return addAgeHeaderEnabled;
    }

    public void setAddAgeHeaderEnabled(boolean addAgeHeaderEnabled) {

        this.addAgeHeaderEnabled = addAgeHeaderEnabled;
    }
}
