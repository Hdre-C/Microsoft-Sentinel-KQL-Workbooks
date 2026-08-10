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

### Inbound Authentication Map


<img src="https://i.imgur.com/AjZBuOy.png" width="1200" alt="Inbound Authentication Map">


Displays the geographic origin of remote login attempts against virtual machines in the virtual network.

Larger bubbles represent a higher number of login attempts.

### Potential Brute-Force Activity
<p align="center">
  <img src="https://i.imgur.com/5XoSh3w.png" width="1200" alt="Potential Brute-Force Activity">
</p>
The three IP addresses with the highest number of failed login attempts were:

- **195.178.110.232 (Bulgaria)** — 104 attempts, all failed. Targeted the `root` and `backup` accounts on 1 virtual machine.
- **103.212.182.194 (Thailand)** — 84 attempts, all failed. Targeted the `a`, `admin`, `pc`, `administrator`, and `user` accounts across 2 virtual machines.
- **1.10.187.55 (Thailand)** — 77 attempts, all failed. Targeted the `admin` and `user` accounts across 2 virtual machines.

The repeated attempts against multiple accounts may indicate potential brute-force activity. **No successful logins were observed from any of these IP addresses.**
