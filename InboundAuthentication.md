## 🔐 Workbook 1 — Inbound Authentication

This workbook investigates remote authentication activity against virtual machines within the virtual network.

The query identifies where remote login attempts are coming from, whether those attempts succeeded or failed, which virtual machines were targeted, and which accounts were involved.

### KQL Query

```kusto
// === Inbound auth origins (geo) ===
// Goal: plot WHERE remote logons originate, and whether they succeeded.
DeviceLogonEvents
// Only logons that came over the network from a real external address.
// RemoteIPType filters out the huge volume of private/internal logons,
// which would otherwise return empty coordinates and clutter the map.
| where RemoteIPType == "Public"
| where isnotempty(RemoteIP)
// We care about network + remote-interactive (RDP) logons reaching in.
| where LogonType in ("Network", "RemoteInteractive")
// Enrich the source IP with geolocation (country/city/lat/long).
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country = tostring(geo.country),
         City = tostring(geo.city)
// Drop rows the geo DB couldn't resolve (no coordinates = nothing to plot).
| where isnotempty(Latitude) and isnotempty(Longitude)
// Aggregate per source location so the map plots one bubble per origin.
// Successes vs failures are counted separately to expose the dangerous mix.
| summarize Attempts = count(),
            Successes = countif(ActionType == "LogonSuccess"),
            Failures = countif(ActionType == "LogonFailed"),
            TargetedDevices = dcount(DeviceName),
            Accounts = make_set(AccountName, 25)
    by RemoteIP, Country, City, Latitude, Longitude
// Label shown on the bubble: IP + country, plus how many succeeded.
| extend MapLabel = strcat(RemoteIP, " (", Country, ") — ", Successes, " success / ", Attempts, " total")
| project Latitude, Longitude, MapLabel, Attempts, Successes, Failures, TargetedDevices, RemoteIP, Country, City, Accounts
| order by Successes desc, Attempts desc
```

### Inbound Authentication Map Overview


<p align="center">
  <img src="https://i.imgur.com/QgLpUwg.png" width="1200" alt="Inbound Authentication Overview">
</p>


Displays the geographic origin of remote login attempts against virtual machines in the virtual network.

The map shows where the login attempts originated, while the table provides details such as total attempts, successful and failed logins, targeted virtual machines, and account names used.

- 🔴 **Red** = 0 or very few successful logins
- 🟠/🟡 **Orange/Yellow** = some successful logins
- 🟢 **Green** = more successful logins

The bubble to fear is a LogonSuccess from a country the virtual network does not operate in. The virtual network operates in the US only so we can assume majority of US based logons are authorized users of the virtual network. 

<h2><u>Data Analysis (last 24 Hours) </u></h2>

### 🔴 Potential Brute-Force Activity
<p align="center">
  <img src="https://i.imgur.com/kIMPU4V.png" width="1200" alt="Potential Brute-Force Activity">
</p>
The three IP addresses with the highest number of failed login attempts were:

- **178.57.110.29 (Russia)** — 368 attempts, all failed. Targeted multiple accounts across 5 virtual machines.
- **48.217.82.109 (United States)** — 153 attempts, all failed. Targeted the `student`, `azureuser`, `azureadmin`, `azurevps`, `azuredp`, and `azureserver` accounts across 6 virtual machines.
- **45.227.254.151 (Panama)** — 119 attempts, all failed. Targeted the `administrator` account across 3 virtual machines.

The repeated attempts against multiple accounts may indicate potential brute-force activity. **No successful logins were observed from any of these IP addresses.**

### 🟢 Successful Login Investigation

The IP address **112.133.200.242 (India)** was identified with suspicious remote authentication activity:

- **72 total login attempts**
- **33 successful logins**
- **39 failed login attempts**
- **1 virtual machine targeted**
- **`administrator` account used**

<p align="center">
  <img src="https://imgur.com/xtNFPKc.png" width="1200" alt="Successful Login Investigation">
</p>
<p align="center">
  <img src="https://i.imgur.com/gSdL9oD.png" width="1200" alt="Successful Login Investigation">
</p>

#### Part 2 — Authentication Timeline

To investigate the suspicious IP further, I filtered `DeviceLogonEvents` for **112.133.200.242** and ordered the authentication events by time.

**KQL Query:**

```kusto
DeviceLogonEvents
| where RemoteIP == "112.133.200.242"
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteIP
| order by Timestamp asc
```

<p align="center">
  <img src="https://i.imgur.com/Jms1Qxi.png" width="1200" alt="Authentication Timeline">
</p>

The first recorded authentication attempt from **112.133.200.242** occurred at **6:28:27 PM** and targeted the `administrator` account on **win-server-2026.corp.com**. The login attempt failed.

<p align="center">
  <img src="https://i.imgur.com/2W3IOXy.png" width="1200" alt="Authentication Investigation">
</p>

The first successful authentication occurred at **6:38:04 PM**, approximately 9 minutes after the failed login activity began.

**Key Findings:**

- **Source IP:** `112.133.200.242`
- **Target VM:** `win-server-2026.corp.com`
- **Account:** `administrator`
- **First observed attempt:** 6:28:27 PM
- **First successful login:** 6:38:04 PM

## Part 3 — Post-Compromise Activity Investigation

After identifying the successful authentication from **112.133.200.242**, I investigated process activity on **win-server-2026.corp.com** to determine what occurred after the account was accessed.

`DeviceProcessEvents` was used to find the activity performed under the `administrator` account

```kusto
DeviceProcessEvents
| where DeviceName == "win-server-2026.corp.com"
| where Timestamp >= datetime(8/11/26 18:38:04)
| where AccountName == "administrator"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

### 1. Remote Command Execution — 6:38:04 PM

After the successful login, `WinrsHost.exe` launched under the `administrator` account and spawned `cmd.exe`.

This indicates that remote commands began executing on the virtual machine immediately after authentication.

![Workbook Image](https://i.imgur.com/bAkf7Za.png)

---

### 2. System Reconnaissance — 6:38:11 PM to 6:38:18 PM

The attacker began gathering information about the system and preparing the machine for additional activity.

Observed activity included:

* Inspecting the Windows Startup folder
![Workbook Image](https://imgur.com/dRm4bl7.png)
The command line decodes to "Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\'"
  
* Identifying the operating system
![Workbook Image](https://imgur.com/hTWmSPI.png)

* Creating `C:\users\Migration`
![Workbook Image](https://imgur.com/7s2zHBN.png)
Decoded PowerShell "New-Item -Path "C:\users\Migration" -ItemType Directory" 
  
* Inspecting Microsoft Defender settings
![Workbook Image](https://imgur.com/gn3LRq1.png)
Decoded PowerShell "Get-MpPreference | fl DisableRealtimeMonitoring, ExclusionPath"
---

### 3. Microsoft Defender Tampering — 6:38:21 PM to 6:38:24 PM

Shortly after performing reconnaissance, PowerShell commands were used to modify Microsoft Defender.

Real-time monitoring was disabled and multiple Defender exclusion paths were added, including the newly created `C:\users\Migration` directory.

<p align="center">
  <img src="SCREENSHOT-URL-HERE" width="1200" alt="Microsoft Defender Tampering">
</p>

---

### 4. Payload Downloads — 6:38:39 PM to 6:38:50 PM

Multiple executable files were downloaded from the external IP address **77.110.114.53**.

The downloaded files included:

* `MicrosoftPrt.exe`
* `svchosl.exe`
* `run.exe`
* `Wmiic.exe`
* `browse.exe`

Several files were placed inside `C:\users\Migration`, while others were placed inside the Windows Startup directory.

<p align="center">
  <img src="SCREENSHOT-URL-HERE" width="1200" alt="Payload Downloads">
</p>

---

### 5. Persistence Established — 6:39:00 PM

The downloaded `Wmiic.exe` executable was then used to install a service named `WMServices`.

The service was configured to execute `svchosl.exe`, establishing persistence on the compromised virtual machine.

<p align="center">
  <img src="SCREENSHOT-URL-HERE" width="1200" alt="Persistence Established">
</p>

---

### Attack Timeline

```text
6:38:04 PM — Successful administrator authentication
     ↓
6:38:04 PM — Remote command execution begins
     ↓
6:38:11–6:38:18 PM — System reconnaissance
     ↓
6:38:21–6:38:24 PM — Microsoft Defender tampering
     ↓
6:38:39–6:38:50 PM — Payloads downloaded
     ↓
6:39:00 PM — Persistence established using WMServices
```

The process activity following the successful authentication provides evidence that the account was used to execute commands, weaken endpoint security controls, download additional executables, establish persistence, and obtain SYSTEM-level execution on the affected virtual machine.

