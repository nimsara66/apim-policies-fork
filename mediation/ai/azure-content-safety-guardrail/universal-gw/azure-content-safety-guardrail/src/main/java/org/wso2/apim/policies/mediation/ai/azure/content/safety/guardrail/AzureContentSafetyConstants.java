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

package org.wso2.apim.policies.mediation.ai.azure.content.safety.guardrail;

public class AzureContentSafetyConstants {
    public static final int GUARDRAIL_ERROR_CODE = 446;
    public static final int GUARDRAIL_APIM_EXCEPTION_CODE = 900514;
    public static final String ERROR_TYPE = "ERROR_TYPE";
    public static final String CUSTOM_HTTP_SC = "CUSTOM_HTTP_SC";
    public static final String FAULT_SEQUENCE_KEY = "custom_fault";
    public static final String ASSESSMENT_ACTION = "action";
    public static final String INTERVENING_GUARDRAIL = "interveningGuardrail";
    public static final String DIRECTION = "direction";
    public static final String AZURE_CONTENT_SAFETY_PROMPT_GUARD = "AZURE_CONTENT_SAFETY_PROMPT_GUARD";
    public static final String AZURE_CONTENT_SAFETY_CONTENT_MODERATION = "AZURE_CONTENT_SAFETY_CONTENT_MODERATION";
    public static final int APIM_INTERNAL_EXCEPTION_CODE = 900967;
    public static final String ASSESSMENT_REASON = "actionReason";
    public static final String ASSESSMENTS = "assessments";
    public static final String TEXT_CLEAN_REGEX = "^\"|\"$";

    public static final String GUARDRAIL_PROVIDER_TYPE = "azure-contentsafety";
    public static final String AZURE_CONTENT_SAFETY_PROMPT_SHIELD_ENDPOINT =
            "/contentsafety/text:shieldPrompt?api-version=2024-09-01";
    public static final String AZURE_CONTENT_SAFETY_CONTENT_MODERATION_ENDPOINT =
            "/contentsafety/text:analyze?api-version=2024-09-01";
}
