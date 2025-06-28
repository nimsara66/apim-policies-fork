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
