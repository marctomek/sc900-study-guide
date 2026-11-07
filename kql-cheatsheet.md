# KQL Cheatsheet (with SPL equivalents)

[← Back to README](README.md)

KQL (Kusto Query Language) is used in Microsoft Sentinel, Defender advanced hunting and Log Analytics.
A query starts with a **table** and pipes it through operators, just like SPL.

## SPL → KQL

| Task | SPL | KQL |
| --- | --- | --- |
| Pick the data source | `index=main sourcetype=x` | `SigninLogs` (start with the table) |
| Time range | time picker / `earliest=-24h` | `where TimeGenerated > ago(24h)` |
| Filter | `search` / `where status=404` | `where Status == 404` |
| Choose columns | `table a, b` / `fields` | `project a, b` |
| Drop columns | `fields - a` | `project-away a` |
| Rename | `rename a AS b` | `project-rename b = a` |
| New field | `eval x = a * 2` | `extend x = a * 2` |
| Count by field | `stats count by user` | `summarize count() by User` |
| Distinct count | `stats dc(user)` | `summarize dcount(User)` |
| First N rows | `head 10` | `take 10` |
| Sort | `sort - count` | `sort by count_ desc` |
| Top values | `top 10 user` | `top 10 by Count` |
| Unique values | `dedup user` | `distinct User` |
| Over time | `timechart span=1h count` | `summarize count() by bin(TimeGenerated, 1h)` then `render timechart` |
| Extract with regex | `rex field=_raw "(?<x>...)"` | `extend x = extract("...", 1, Field)` or `parse` |
| Join | `join user [search ...]` | `join kind=inner (OtherTable) on User` |

## Comparison operators

| Operator | Meaning |
| --- | --- |
| `==` / `!=` | Equals / not equals (case-sensitive) |
| `=~` / `!~` | Equals / not equals (case-insensitive) |
| `has` | Contains a whole term (fast, preferred) |
| `contains` | Contains a substring (slower) |
| `startswith` / `endswith` | Starts or ends with |
| `in (...)` | Matches any value in a list |
| `isnotempty(x)` | Field has a value |

## Useful tables

| Table | Where | Contents |
| --- | --- | --- |
| `SigninLogs` | Sentinel | Entra ID interactive sign-ins |
| `AuditLogs` | Sentinel | Entra ID changes (roles, apps, users) |
| `SecurityEvent` | Sentinel | Windows security events (e.g. 4624, 4625) |
| `OfficeActivity` | Sentinel | Microsoft 365 audit log |
| `SecurityIncident` / `SecurityAlert` | Sentinel | Sentinel incidents and alerts |
| `DeviceProcessEvents` | Defender | Processes started on devices |
| `EmailEvents` | Defender | Email delivery and threats |
| `IdentityLogonEvents` | Defender | AD and Entra logons from Defender for Identity |

## Gotchas

- Sentinel tables use `TimeGenerated`. Defender advanced hunting tables use `Timestamp`.
- `==` is case-sensitive. Use `=~` when you're not sure about the case.
- `summarize count()` names the column `count_`, so sort with `sort by count_ desc`.
- Prefer `has` to `contains`: it's faster and matches whole terms.

## Queries from my labs

```kql
// Password spray: one IP failing against many accounts (02-entra.md)
SigninLogs
| where ResultType == "50126"
| summarize FailedUsers = dcount(UserPrincipalName) by IPAddress
| where FailedUsers > 10

// Encoded PowerShell (03-security-solutions.md)
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has "-enc"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```
