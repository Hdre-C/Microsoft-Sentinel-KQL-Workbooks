# Microsoft Sentinel KQL Workbooks

This repository contains Microsoft Sentinel workbooks I created to visually investigate security activity across Azure virtual networks (VNets) and the virtual machines within them using KQL (Kusto Query Language).

The workbooks analyze authentication activity, network connections, data movement, and threat intelligence to provide visibility into potentially suspicious activity involving virtual machines and their network traffic.

## Workbooks

### 1. Inbound Authentication 

**Location:** `InboundAuthentication`

This workbook investigates remote authentication attempts against virtual machines within the virtual network.

It provides visibility into:
- Successful and failed remote login attempts
- External source IP addresses and their geographic locations
- Accounts being targeted
- Virtual machines being targeted
- Total authentication attempts from each source

This can help identify suspicious activity such as repeated failed login attempts or successful remote logins from unusual external locations.

---

### 2. Outbound C2 Communication 

**Location:** `OutboundC2Communication`

This workbook investigates outbound connections made by virtual machines within the virtual network to external IP addresses.

It provides visibility into:
- External destinations contacted by virtual machines
- Number of outbound connections
- Virtual machines communicating with each destination
- Processes responsible for the connections
- Destination ports
- Geographic locations of external destinations

Common Microsoft traffic is filtered out to reduce noise and make unusual outbound connections easier to investigate.
