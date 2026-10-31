# Windows Endpoint Monitoring & File Integrity Monitoring (Wazuh)

## Current Active Lab Architecture

**SIEM & Endpoint Infrastructure:** 
  * Ubuntu Server Manager acting as the central log collector and manager.
  * Connected Windows 11 endpoint running active agent monitoring.
  * Direct SSH access configured from local host to Ubuntu Manager to run locally

## Skills & Tools

Wazuh SIEM • Windows Event Logs • File Integrity Monitoring (FIM) • Authentication Event Analysis • Endpoint Monitoring • Virtualization

---

## Key Activities

* Deployed a Wazuh Manager on a virtual machine and integrated a Wazuh Agent on a Windows endpoint.

* Configured and validated agent connectivity to establish centralized endpoint log collection.

* Captured and analyzed failed Windows authentication events to investigate unsuccessful login attempts.

* Implemented File Integrity Monitoring (FIM) on a designated project directory to detect file changes and monitor endpoint activity.

* Reviewed generated security alerts and endpoint telemetry through the Wazuh dashboard.

* Instead of treating logon events uniformly, we map raw Windows Event IDs and context to a custom severity matrix (from Level 5 / Low up to Level 15 / Very Critical).

### Criticality Rating Matrix

| Event ID | Description | Context / Condition | Risk Level | Wazuh Alert Level |
| :--- | :--- | :--- | :--- | :--- |
| **4624** | Logon Success | Standard local interactive user login | **Low** | Level 3 – 5 |
| **4624** | Logon Success | Remote Interactive / RDP (`LogonType 10`) | **Medium** | Level 7 |
| **4625** | Single Logon Failure | Incorrect password attempt | **Medium** | Level 5 – 7 |
| **4625** | Multiple Failures | 5+ failures within 60 seconds (Potential Brute Force) | **High** | Level 10 |
| **4625 / 4624** | Critical Sequence | Repeated failures followed by a successful logon | **Very Critical** | Level 14 – 15 |


### Implementation Blueprint for This Phase

* **Custom XML Rule Overrides**: Create custom rules in `/var/ossec/etc/rules/local_rules.xml` to parse `data.win.system.eventId` along with specific sub-fields like `data.win.eventdata.logonType`.
* **Frequency & Correlation Engine**: Utilize `<frequency>` and `<if_matched_sid>` XML tags to automatically escalate alert levels when events repeat rapidly or follow suspicious patterns.
* **Notification Routing**: Configure Wazuh's notification engine (`<reports>` / `<email_alerts>`) or Webhook integrations (Discord, Slack, or Telegram) to fire immediate alerts whenever an event exceeds **Level 10 (High)** or **Level 14+ (Very Critical)**. (In process)
