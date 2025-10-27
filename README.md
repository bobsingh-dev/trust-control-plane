🔐 Trust Control Plane

Authenticate → Authorize → Attest → Assure

A working prototype demonstrating how to build a Zero-Trust microservice system using mTLS, Open Policy Agent (OPA), and SPIFFE-style workload identities.

🎯 Goal

Design a real-world trust pipeline where workloads authenticate, authorize, and prove attestation before being allowed to communicate — the same concepts that underpin modern identity-driven security systems for AI and microservices.

⚙️ Stack

Go – for backend services

OPA (Rego) – for policy enforcement

Docker Compose – to orchestrate the stack

Python – for audit log analysis and trust scoring

YAML + OpenSSL – for configuration and cert management

🧩 Architecture Overview
Component	Purpose
🧱 Service A	Protected API enforcing mTLS and OPA authorization
🚀 Service B	Client microservice with SPIFFE-style identity
🧠 OPA	Evaluates Rego policies: only attested workloads allowed
🧾 Log Job	Parses audit logs → computes real-time trust score
🔐 CertGen	Generates demo CA + short-lived certificates
🧰 Run the Demo
# 1️⃣ Generate certificates
docker compose --profile tools up certgen

# 2️⃣ Launch all components
docker compose up --build


You’ll see:

opa-1        | {"msg":"Server running","level":"info"}
serviceA-1   | ✅ access granted to spiffe://trust.local/serviceB
serviceB-1   | status=200 body={"status":"ok","message":"access granted"}
logjob-1     | [trust-score] allow=8 deny=0 score=1.0000

🔎 Concepts Demonstrated

Mutual TLS authentication between microservices

SPIFFE-style identity URIs embedded in X.509 certs

OPA policy enforcement for authorization decisions

Attestation chaining through verified workload identities

Continuous assurance via audit logging and trust scoring
