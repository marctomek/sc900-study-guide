# Microsoft SC-900 — Study Guide

My study notes for **SC-900: Microsoft Security, Compliance, and Identity Fundamentals**,
organized by the official
[study guide](https://learn.microsoft.com/certifications/resources/study-guides/sc-900)
(skills measured as of 28 July 2026). Every concept is written in my own words and,
where possible, demonstrated with queries and screenshots from my own hands-on labs.

## About the exam

| | |
| --- | --- |
| Questions | About 40–60 |
| Time | 45 minutes |
| Passing score | 700 / 1000 |
| Level | Fundamentals |
| Prerequisites | None |

## Domains

| # | Domain | Weight | Notes | Status |
| --- | --- | --- | --- | --- |
| 1 | Concepts of security, compliance, and identity | 10–15% | [01-concepts.md](01-concepts.md) | ⬜ |
| 2 | Capabilities of Microsoft Entra | 25–30% | [02-entra.md](02-entra.md) | ⬜ |
| 3 | Capabilities of Microsoft security solutions | 35–40%* | [03-security-solutions.md](03-security-solutions.md) | ⬜ |
| 4 | Capabilities of Microsoft compliance solutions | 20–25%* | [04-compliance.md](04-compliance.md) | ⬜ |

\*Weights from the previous exam version. Check them against the official study guide.

Domains 2 and 3 are well over half the exam, so they get the most labs.

Quick reference: [kql-cheatsheet.md](kql-cheatsheet.md) (KQL with SPL equivalents)

## How each topic is written

```
### <objective number> <topic>
Concept       — what it is, in plain words
Lab           — what I did, plus the KQL query I ran (where one applies)
Result        — screenshot or short output from my lab
Why it works  — what the query or setting does and why it matters
Exam trap     — the detail most likely to be tested
```

SC-900 is a concepts exam, so some topics have no query. Those use a portal screenshot instead.

## Lab environment

Labs were done in TryHackMe cloud environments and Microsoft's free resources, so readers can reproduce them:

- TryHackMe [M365 Monitoring module](https://tryhackme.com/module/m365-monitoring-soc): M365 Monitoring Basics, Entra ID Monitoring
- TryHackMe [KQL module](https://tryhackme.com/module/kql): KQL (Kusto) Introduction, Basic Queries, Advanced Queries
- TryHackMe Defending Azure path: XDR: Introduction
- Microsoft Learn SC-900 learning path exercises (Purview, Defender for Cloud)
- Optional: Microsoft 365 E5 trial tenant for Entra, Defender and Purview portal screenshots

Screenshots live in [`images/`](images/) and are named by objective, for example `2.1-risky-signin.png`.
They are cropped to my own queries and results. This repo contains no room answers, flags,
tenant IDs, or copied course material.

## Progress

- [ ] 1. Security, compliance, and identity concepts (labs 1.1 and 1.2 done)
- [ ] 2. Microsoft Entra
- [ ] 3. Microsoft security solutions
- [ ] 4. Microsoft compliance solutions
- [ ] Self-check passed (see end of each file)
- [ ] Microsoft practice assessment: 80%+ twice
- [ ] Exam booked
