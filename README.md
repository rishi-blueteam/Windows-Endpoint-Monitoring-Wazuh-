# SOC Lab Implementation: Active Stack & Enhanced Event Scoring

## Current Active Lab Architecture

* **SIEM & Endpoint Infrastructure:** 
  * Ubuntu Server Manager acting as the central log collector and manager.
  * Connected Windows 11 endpoint running active agent monitoring.
  * Direct SSH access configured from local host to Ubuntu Manager.

* **File Integrity Monitoring (FIM):** 
  * Active `syscheck` module configured with `realtime="yes"` tracking critical system directories (`C:\Windows\System32`).
  * Validated detection capabilities for remote file additions, modifications, and deletions initiated via RDP and SMB administrative shares.(iin development)

* **Phishing Ingestion & Detection Pipeline:**
  * Custom Python fetcher (`/opt/gmail_fetcher.py`) reading unread messages from Gmail via IMAP and 2FA App Passwords.
  * JSON-formatted log pipeline outputting directly to `/var/log/phishing_detector.log`.
  * Custom Wazuh rules (`100200` base JSON decoder and `100201` Level 12 critical alert) triggering on suspicious keywords in subject lines.

---

## Targeted Upgrade: Dynamic Windows Event Rating & Alerting

Instead of treating logon events uniformly, we map raw Windows Event IDs and context to a custom severity matrix (from Level 5 / Low up to Level 15 / Very Critical).

### Criticality Rating Matrix

| Event ID | Description | Context / Condition | Risk Level | Wazuh Alert Level |
| :--- | :--- | :--- | :--- | :--- |
| **4624** | Logon Success | Standard local interactive user login | **Low** | Level 3 – 5 |
| **4624** | Logon Success | Remote Interactive / RDP (`LogonType 10`) | **Medium** | Level 7 |
| **4625** | Single Logon Failure | Incorrect password attempt | **Medium** | Level 5 – 7 |
| **4625** | Multiple Failures | 5+ failures within 60 seconds (Potential Brute Force) | **High** | Level 10 |
| **4625 / 4624** | Critical Sequence | Repeated failures followed by a successful logon | **Very Critical** | Level 14 – 15 |

### Implementation Blueprint for This Phase

* **Custom XML Rule Overrides:** Create custom rules in `/var/ossec/etc/rules/local_rules.xml` to parse `data.win.system.eventId` along with specific sub-fields like `data.win.eventdata.logonType`.
* **Frequency & Correlation Engine:** Utilize `<frequency>` and `<if_matched_sid>` XML tags to automatically escalate alert levels when events repeat rapidly or follow suspicious patterns.
* **Notification Routing:** Configure Wazuh's notification engine (`<reports>` / `<email_alerts>`) or Webhook integrations (Discord, Slack, or Telegram) to fire immediate alerts whenever an event exceeds **Level 10 (High)** or **Level 14+ (Very Critical)**.
