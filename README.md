# Windows Endpoint Monitoring & File Integrity Monitoring (Wazuh)

## Current Active Lab Architecture

**SIEM & Endpoint Infrastructure:** 
  * Ubuntu Server Manager acting as the central log collector and manager.
  * Connected Windows 11 endpoint running an active agent for monitoring.
  * Direct SSH access configured from the local host to the Ubuntu Manager to run locally

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


## Implementation Blueprint for This Phase
* **Wazuh Server Installation:**
* **Wazuh Agent Installation:**
* **Custom XML Rule Overrides for Windows File Event Monitoring**: Create custom rules in `/var/ossec/etc/rules/local_rules.xml` to parse `data.win.system.eventId` along with specific sub-fields like `data.win.eventdata.logonType`.
* **Notification Routing**: Configure Wazuh's notification engine (`<reports>` / `<email_alerts>`) or Webhook integrations (Discord, Slack, or Telegram) to fire immediate alerts whenever an event exceeds **Level 10 (High)** or **Level 14+ (Very Critical)**. (In process)

### Implementation Phase Steps

#### Wazuh Server Installation

* In the first step, we install the Wazuh server on our VM via the GitHub link:

![alt text](SOC-Home-Lab-Images/Ubuntu%20Wazuh%20Server%20Download%20via%20github.png) 

![alt text](SOC-Home-Lab-Images/Wazuh%20Bash%20Run%20for%20Hosting%20Process.png)

* Once it's loaded, we get our default server, and we get our password: 

![alt text](SOC-Home-Lab-Images/Server%20Installed%20Successfully.png)

* Now let's run Wazuh generally to see if things are working, and yes it does
![alt text](SOC-Home-Lab-Images/Wazuh%20Installed.png)

#### Wazuh Agent Installation on Windows VM

* Let's now push the agent on the Windows client by installing it.

![Alt Text](SOC-Home-Lab-Images/Windows%20Wazuh%20Agent%20Deployment.png)

* After multiple freaking configurations that were tough to deal with, comes the part where the agent is up and running while it communicates with the server.

![Alt Text](Wazuh%20Service%20Started%20on%20Windows%20Client%20Successfully.png)

#### The Password Authentication Failed Attack

* We will now sign out of the Windows VM to come to the main login screen to enter the password.
* After we enter the wrong password about three times, then comes the part where we actually find the event alert on the Wazuh Dashboard.
* So this time we enter the password correctly, and the login to the account becomes successfull
* We go to the dashboard and filter events out.

![alt text](SOC-Home-Lab-Images/Failed%20Attempts%20Login.png)

The brute force will be about how the authentication has failed with respect to the event id

![alt text](SOC-Home-Lab-Images/Brute%20Force%20Attempt%20Logged%20-%204625.png)

* We can do the same for a successful login to the system. As we logged in before this time, we will search for the event ID with respect to the correct number


![alt text](SOC-Home-Lab-Images/Successfull%20Login%20via%20Wazuh.png)
![alt text](SOC-Home-Lab-Images/SOC-Home-Lab-Images/Successfull%20Login%20via%20Wazuh.png)
