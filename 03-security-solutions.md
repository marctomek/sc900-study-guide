# 3. Capabilities of Microsoft Security Solutions (largest domain)

[← Back to README](README.md)

Labs: TryHackMe KQL module (Sentinel) and *XDR: Introduction* (Defender XDR). Azure infrastructure and Defender for Cloud come from Microsoft Learn.

---

### 3.1 Azure infrastructure security

**Concept**

| Service | What it does |
| --- | --- |
| Network security group (NSG) | Allow/deny rules on a subnet or network interface (IP, port, protocol) |
| Azure Firewall | Managed, stateful firewall for whole virtual networks, with threat intelligence |
| Azure DDoS Protection | Protects against flooding attacks |
| Azure Bastion | RDP/SSH to VMs through the browser, with no public IP |
| Web Application Firewall (WAF) | Protects web apps from attacks like SQL injection and XSS |
| Azure Key Vault | Stores secrets, keys and certificates |

**Exam trap** — An NSG filters traffic for a subnet or NIC. Azure Firewall protects across virtual networks. Bastion means you **don't need a public IP** on the VM.

---

### 3.2 Microsoft Defender for Cloud

**Concept** — **CSPM** (cloud security posture management) plus **CWPP** (cloud workload protection). It gives a **Secure Score**, recommendations, and threat alerts for Azure, AWS, GCP and on-premises.

**Lab** — Microsoft Learn exercise: reviewed Secure Score and the top recommendations.

**Result**

![Defender for Cloud Secure Score](images/3.2-secure-score.png)

**Exam trap** — Defender for Cloud covers **multicloud**, not just Azure. Its Secure Score is different from the Microsoft Secure Score in the Defender portal for Microsoft 365.

---

### 3.3 Microsoft Sentinel

**Concept** — A cloud-native **SIEM** (collects and analyses logs) and **SOAR** (automates response). Data lives in a Log Analytics workspace and is queried with KQL. Its parts are data connectors, analytics rules, incidents, workbooks, hunting and playbooks (built on Logic Apps). Sentinel is now built into the Defender portal.

**Lab** — TryHackMe *KQL (Kusto): Introduction* and *Basic Queries*.

**Query**

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625
| summarize FailedLogons = count() by Account, Computer
| top 10 by FailedLogons
```

**Result**

![Sentinel KQL failed logons](images/3.3-sentinel-failed-logons.png)

**Why it works** — Event ID 4625 is a failed Windows logon. `top 10 by` sorts and limits in one step, like `stats ... | sort - | head 10` in SPL.

**Exam trap** — SIEM = **collect and detect**. SOAR = **automate the response** (playbooks). Sentinel does both.

---

### 3.4 Microsoft Defender XDR

**Concept** — Extended detection and response. It links alerts from every Defender product into one **incident**.

| Product | Protects |
| --- | --- |
| Defender for Endpoint | Devices (EDR, attack surface reduction) |
| Defender for Office 365 | Email and collaboration: phishing, Safe Links, Safe Attachments |
| Defender for Identity | On-premises Active Directory (uses domain controller signals) |
| Defender for Cloud Apps | SaaS apps (CASB, shadow IT discovery) |
| Defender Vulnerability Management | Weaknesses and missing patches across devices |
| Microsoft Defender Threat Intelligence | Threat actor and indicator information |

**Lab** — TryHackMe *XDR: Introduction*: investigated an incident and hunted for encoded PowerShell.

**Query** (advanced hunting)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-enc"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

**Result**

![XDR incident](images/3.4-xdr-incident.png)

![Advanced hunting encoded PowerShell](images/3.5-advanced-hunting.png)

**Why it works** — Attackers often hide commands with `-enc` (Base64). `=~` is a case-insensitive equals and `has` matches a whole term. Defender tables use `Timestamp`, while Sentinel tables use `TimeGenerated`.

**Exam trap** — Defender for **Identity** = on-premises AD. **Entra ID Protection** = cloud identity. Defender for **Cloud Apps** = SaaS. Defender for **Cloud** = Azure, AWS and GCP workloads.

---

### 3.5 Security Copilot and Exposure Management

**Concept** — **Security Copilot** is the generative AI assistant: it summarises incidents, explains scripts and writes KQL from plain English. **Microsoft Security Exposure Management** shows your attack surface and possible attack paths.

**Exam trap** — Copilot *helps* analysts. It doesn't replace detections or automatically fix things.

---

## Self-check

- [ ] I can explain NSG vs Azure Firewall, and what Bastion is for
- [ ] I can explain CSPM vs CWPP in Defender for Cloud
- [ ] I can explain SIEM vs SOAR, and which Sentinel parts do each
- [ ] I can match each Defender product to what it protects
- [ ] I can write a basic KQL query with `where`, `summarize` and `project`
