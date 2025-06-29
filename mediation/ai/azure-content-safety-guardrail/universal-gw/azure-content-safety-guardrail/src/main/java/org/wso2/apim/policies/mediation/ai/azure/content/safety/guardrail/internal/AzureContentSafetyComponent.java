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

package org.wso2.apim.policies.mediation.ai.azure.content.safety.guardrail.internal;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.GuardrailProviderService;

import org.wso2.apim.policies.mediation.ai.azure.content.safety.guardrail.AzureContentSafetyConstants;

@Component(
    name = "org.wso2.apim.policies.mediation.ai.azure.content.safety.guardrail.internal.AzureContentSafetyComponent",
    immediate = true
)
public class AzureContentSafetyComponent {
    @Reference(
            name = "guardrail.provider.service",
            service = GuardrailProviderService.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unbindProvider"
    )
    protected void bindProvider(GuardrailProviderService provider) throws APIManagementException {
        if (AzureContentSafetyConstants.GUARDRAIL_PROVIDER_TYPE.equalsIgnoreCase(provider.getType())) {
            ServiceReferenceHolder.getInstance().setGuardrailProviderService(provider);
        }
    }

    protected void unbindProvider(GuardrailProviderService provider) {
        if (AzureContentSafetyConstants.GUARDRAIL_PROVIDER_TYPE.equalsIgnoreCase(provider.getType()))
            ServiceReferenceHolder.getInstance().setGuardrailProviderService(null);
    }
}
