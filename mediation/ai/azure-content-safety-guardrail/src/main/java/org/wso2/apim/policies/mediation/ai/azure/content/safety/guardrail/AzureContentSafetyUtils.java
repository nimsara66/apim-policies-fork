package org.wso2.apim.policies.mediation.ai.azure.content.safety.guardrail;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.json.JSONObject;

public class AzureContentSafetyUtils {
    private static final Log logger = LogFactory.getLog(AzureContentSafetyUtils.class);

    /**
     * Extracts JSON content from the message context.
     * This utility method converts the Axis2 message payload to a JSON string.
     *
     * @param messageContext The message context containing the JSON payload
     * @return The JSON payload as a string, or null if extraction fails
     */
    public static String extractJsonContent(MessageContext messageContext) {
        org.apache.axis2.context.MessageContext axis2MC =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        return JsonUtil.jsonPayloadToString(axis2MC);
    }

    /**
     * Builds a JSON object containing assessment details for guardrail responses.
     * This JSON includes information about why the guardrail intervened.
     *
     * @return A JSON string representing the assessment object
     */
    public static String buildAssessmentObject(String name, boolean buildAssessment) {
        if (logger.isDebugEnabled()) {
            logger.debug("RegexGuardrail: Building assessment");
        }

        JSONObject assessmentObject = new JSONObject();

        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_ACTION, "GUARDRAIL_INTERVENED");
        assessmentObject.put(AzureContentSafetyConstants.INTERVENING_GUARDRAIL, name);
        assessmentObject.put(AzureContentSafetyConstants.ASSESSMENT_REASON, "Violation of regular expression detected.");

        if (buildAssessment) {
            assessmentObject.put(AzureContentSafetyConstants.ASSESSMENTS,
                    "Violated regular expression: ");
        }
        return assessmentObject.toString();
    }
}
