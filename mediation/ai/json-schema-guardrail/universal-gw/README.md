# JSON Schema Guardrail Mediator for WSO2 API Manager Universal Gateway

The **JSON Schema Guardrail** is a custom Synapse mediator for **WSO2 API Manager Universal Gateway**, designed to validate JSON payloads against a user-defined **JSON Schema**. This mediator enables API publishers to enforce structural and content compliance dynamically in both request and response flows.

---

## ✨ Features

- ✅ Validate payload structure and fields using **JSON Schema**
- ✅ Target specific segments of a payload using **JSONPath**
- ✅ Support for **inverted validation** (fail when schema matches)
- ✅ **Guardrail assessment** for better observability on violations
- ✅ Works on both **request and response** flows
- ✅ Integrates with WSO2 **fault sequences** on failure

---

## 🛠️ Prerequisites

- Java 11 (JDK)
- Maven 3.6.x or later
- WSO2 API Manager or Synapse-compatible runtime

---

## 📦 Building the Project

To compile and package the mediator:

```bash
mvn clean install
```

> ℹ️ This will generate a `.zip` file in the `target/` directory containing the mediator JAR, `policy-definition.json`, and `artifact.j2`.

---

## 🚀 How to Use

Follow these steps to integrate the JSON Schema Guardrail policy into your WSO2 API Manager instance:

1. **Unzip the Build Artifact**

```bash
unzip target/org.wso2.apim.policies.mediation.ai.json-schema-guardrail-<version>-distribution.zip -d json-schema-guardrail
```

2. **Copy the Mediator JAR**

```bash
cp json-schema-guardrail/org.wso2.apim.policies.mediation.ai.json-schema-guardrail-<version>.jar $APIM_HOME/repository/components/lib/
```

3. **Register the Policy in Publisher**

- Use the `policy-definition.json` and `artifact.j2` files to define the policy in the Publisher Portal.
- Place them in your custom policy deployment directory or register them using the Admin REST API.

4. **Apply and Deploy the Policy**

- Go to **API Publisher**
- Select your API
- Navigate to **Runtime > Request/Response Flow**
- Click **Add Policy** and choose **JSON Schema Guardrail**
- Configure the policy parameters (name, JSONPath, schema, etc.)
- **Save and Deploy** the API

---

## 🧾 Example Policy Configuration

| Field                       | Example                                              |
|-----------------------------|------------------------------------------------------|
| `Guardrail Name`            | `Response Format Validator`                          |
| `JSON Schema`               | (Insert your JSON Schema here as a string)           |
| `JSON Path`                 | `$.data.content`                                     |
| `Invert the Decision`       | `false`                                              |
| `Show Guardrail Assessment` | `true`                                               |

---

## 🔍 Example Input

```json
{
  "data": {
    "content": {
      "user": "John",
      "age": 29
    }
  }
}
```

**Schema Example**:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "user": { "type": "string" },
    "age": { "type": "integer", "minimum": 18 }
  },
  "required": ["user", "age"]
}
```

---

## 🚫 Example Error Response

If the payload fails the validation, an error response like below will be returned:

```json
{
  "error": {
    "code": "JSON_SCHEMA_GUARDRAIL_VIOLATION",
    "message": "The request violates the JSON Schema Guardrail policy: 'Response Format Validator'.",
    "assessment": {
      "interveningGuardrail": "Response Format Validator",
      "direction": "RESPONSE",
      "reason": "Violation of enforced JSON schema detected.",
      "assessments": "The inspected response payload content: {...} does not satisfy the JSON schema: {...}"
    }
  }
}
```

---
