# URL Guardrail Mediator for WSO2 API Manager Universal Gateway

The **URL Guardrail** is a custom Synapse mediator for **WSO2 API Manager Universal Gateway**, designed to perform **URL validity checks** on incoming or outgoing JSON payloads. This component acts as a *guardrail* to enforce content safety by validating embedded URLs for accessibility or DNS resolution.

---

## ✨ Features

- ✅ Validate payload content by extracting and checking URLs
- ✅ Perform either **DNS resolution** or **HTTP HEAD** validation
- ✅ Target specific fields in JSON payloads using **JSONPath**
- ✅ Configure custom **timeout** for validation checks
- ✅ Trigger fault sequences on rule violations
- ✅ Include optional **assessment messages** in error responses for better observability

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

> ℹ️ This will generate a `.zip` file in the `target/` directory containing the mediator JAR, policy-definition.json, and artifact.j2.

---

## 🚀 How to Use

Follow these steps to integrate the URL Guardrail policy into your WSO2 API Manager instance:

1. **Unzip the Build Artifact**

```bash
unzip target/org.wso2.apim.policies.mediation.ai.url-guardrail-<version>-distribution.zip -d url-guardrail
```

2. **Copy the Mediator JAR**

```bash
cp url-guardrail/org.wso2.apim.policies.mediation.ai.url-guardrail-<version>.jar $APIM_HOME/repository/components/lib/
```

3. **Register the Policy in Publisher**

- Use the `policy-definition.json` and `artifact.j2` files to define the policy in the Publisher Portal.
- Place them appropriately in your custom policy deployment directory or register via the REST API.

4. **Apply and Deploy the Policy**

- Go to **API Publisher**
- Select your API
- Navigate to **Runtime > Request/Response Flow**
- Click **Add Policy** and choose **URL Guardrail**
- Configure the policy parameters (name, JSONPath, timeout, etc.)
- **Save and Deploy** the API

---

## 🧾 Example Policy Configuration

| Field                       | Example                  |
|-----------------------------|--------------------------|
| `Guardrail Name`            | `URL Safety Guard`       |
| `JSON Path`                 | `$.messages[-1].content` |
| `Connection Timeout`        | `500` (in milliseconds)  |
| `Perform DNS Lookup`        | `false`                  |
| `Show Guardrail Assessment` | `false`                  |

---

## 🔍 Example Input

```json
{
  "messages": [
    {
      "role": "user",
      "content": "Check out https://example.invalid or http://test.fake"
    }
  ]
}
```

If either of the URLs fail to respond or resolve, the following error response will be returned:

```json
{
  "error": {
    "code": "URL_GUARDRAIL_VIOLATION",
    "message": "The request violates the URL Guardrail policy: 'URL Safety Guard'.",
    "assessment": {
      "message": "One or more URLs in the payload failed validation.",
      "invalidUrls": [
        "https://example.invalid",
        "http://test.fake"
      ]
    }
  }
}
```

---
