package org.wso2.apim.policies.mediation.ai.azure.content.safety.guardrail.internal;

import org.wso2.carbon.apimgt.api.GuardrailProviderService;

/**
 * Singleton holder for managing references to shared services like AzureContentSafetyGuardrailProviderService.
 */
public class ServiceReferenceHolder {
    private static final ServiceReferenceHolder instance = new ServiceReferenceHolder();

    private GuardrailProviderService guardrailProviderService;

    private ServiceReferenceHolder() {
    }

    public static ServiceReferenceHolder getInstance() {
        return instance;
    }

    public GuardrailProviderService getGuardrailProviderService() {
        return guardrailProviderService;
    }

    public void setGuardrailProviderService(GuardrailProviderService guardrailProviderService) {
        this.guardrailProviderService = guardrailProviderService;
    }
}
