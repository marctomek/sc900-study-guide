# 1. Concepts of Security, Compliance, and Identity (10–15%)

[← Back to README](README.md)

This domain is mostly vocabulary. The goal is to explain each term in one sentence.

---

### 1.1 Zero Trust

**Concept** — Never trust a request automatically, even from inside the network. Three principles:
**verify explicitly**, **use least-privilege access**, **assume breach**. Applied across six pillars:
identities, devices, applications, data, infrastructure, networks.

**Lab** — TryHackMe *M365 Monitoring Basics* (Task 4, Entra ID sign-in logs): pulled failed sign-ins to see what Entra records about each attempt.

**Query** (SPL, as run in the lab)

```spl
index=scenario sourcetype="azure:aad:signin" "status.errorCode"!=0
| table createdDateTime userPrincipalName appDisplayName ipAddress location.city status.errorCode status.failureReason conditionalAccessStatus
| head 10
```

**KQL equivalent** (Microsoft Sentinel)

```kql
SigninLogs
| where ResultType != "0"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, City = tostring(LocationDetails.city), ResultType, ResultDescription, ConditionalAccessStatus
| take 10
```

**Result**

![Failed Entra ID sign-ins](images/1.1-signin-entry.png)

*User and IP address redacted.*

**Why it works** — Every sign-in is checked and logged on its own signals: user, app, IP, location and result ("verify explicitly"). Here one account fails repeatedly within seconds from the same IP with error 50126 (invalid username or password), which is a brute-force pattern. `conditionalAccessStatus = notApplied` shows no Conditional Access policy stepped in. Logging every attempt is what makes this visible ("assume breach").

**Exam trap** — Zero Trust is a *strategy*, not a product. The third principle is "assume **breach**", not "assume trust".

---

### 1.2 Shared responsibility model

**Concept** — The cloud provider and the customer split security duties. The split depends on the service type.

| Service type | Microsoft secures | You secure |
| --- | --- | --- |
| SaaS (Microsoft 365) | Apps, OS, hosts, network, physical | Data, devices, accounts and identities |
| PaaS (Azure App Service) | OS, hosts, network, physical | Above + applications |
| IaaS (Azure VMs) | Hosts, network, physical | Above + operating system |
| On-premises | Nothing | Everything |

**Exam trap** — The customer is **always** responsible for information and data, devices, and accounts and identities, whatever the service type.

---

### 1.3 Defense in depth and the CIA triad

**Concept** — Defense in depth stacks layers, so one failed layer doesn't expose everything:
physical → identity and access → perimeter → network → compute → application → data.
The CIA triad: **confidentiality** (only the right people see it), **integrity** (it hasn't been changed),
**availability** (it's there when needed).

**Exam trap** — DDoS attacks target **availability**. Tampering targets **integrity**. Data leaks break **confidentiality**.

---

### 1.4 Encryption and hashing

**Concept**
- **Symmetric** encryption: one shared key for encrypting and decrypting.
- **Asymmetric** encryption: a public key encrypts, a private key decrypts.
- **Encryption at rest** (stored data) vs **in transit** (data moving over a network).
- **Hashing**: a one-way fingerprint, used to check integrity and store passwords. **Salting** adds random data before hashing.

**Exam trap** — Hashing **can't be reversed**. Encryption can, with the key.

---

### 1.5 Identity concepts

**Concept**
- **Authentication (AuthN)**: proving who you are.
- **Authorization (AuthZ)**: what you're allowed to do once signed in.
- **Identity provider (IdP)**: a service like Entra ID that handles sign-ins for many apps, using standards such as OAuth 2.0, OpenID Connect and SAML.
- **Single sign-on (SSO)**: one sign-in for many apps.
- **Federation**: trusting another organization's IdP.
- **Directory services**: Active Directory Domain Services (on-premises) vs Entra ID (cloud).

**Lab** — TryHackMe *M365 Monitoring Basics* (Task 5, Entra ID audit logs): listed every account change, showing who made it (initiator) and who it was made to (target).

**Query** (SPL, as run in the lab)

```spl
index=scenario sourcetype="azure:aad:audit"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName', 'initiatedBy.app.displayName')
| table _time activityDisplayName initiator targetResources{}.userPrincipalName result
```

**KQL equivalent** (Microsoft Sentinel)

```kql
AuditLogs
| extend Initiator = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName))
| extend Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Initiator, Target, Result
```

**Result**

![Entra ID audit log entries](images/1.2-audit-entry.png)

*User names redacted.*

**Why it works** — A change can be made by a person or by a Microsoft service, so `coalesce` takes whichever initiator field has a value. The log shows a user registering new security info (an MFA method) and then running a self-service password reset. After a compromise, this pattern can mean an attacker is locking in access.



**Exam trap** — AuthN always comes **before** AuthZ. Federation does **not** need the two organizations to share a directory.

---

### 1.6 Compliance concepts

**Concept**
- **Data residency**: where data is physically stored.
- **Data sovereignty**: data is subject to the laws of the country where it's stored.
- **Data privacy**: being open about how personal data is collected and used (e.g. GDPR).
- **GRC**: governance (rules), risk (finding and managing threats), compliance (proving you meet regulations).

**Exam trap** — Residency is about *location*. Sovereignty is about *which laws apply*.

---

## Self-check

- [ ] I can name the three Zero Trust principles
- [ ] I know what the customer always owns in the shared responsibility model
- [ ] I can match an attack to the part of the CIA triad it breaks
- [ ] I can explain hashing vs encryption
- [ ] I can explain authentication vs authorization
- [ ] I can explain data residency vs data sovereignty
