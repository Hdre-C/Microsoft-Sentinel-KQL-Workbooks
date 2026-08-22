# Microsoft Sentinel KQL Workbooks

This repository contains Microsoft Sentinel workbooks I created to visually investigate security activity across Azure virtual networks (VNets) and the virtual machines within them using KQL (Kusto Query Language).

The workbooks analyze authentication activity, network connections, data movement, and threat intelligence to provide visibility into potentially suspicious activity involving virtual machines and their network traffic.

## Workbooks

### 1. Inbound Authentication 🔐

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

### 2. Outbound C2 Communication 📡

**Location:** `Workbook-2-Outbound-C2/`

This workbook investigates outbound connections made by virtual machines within the virtual network to external IP addresses.

It provides visibility into:
- External destinations contacted by virtual machines
- Number of outbound connections
- Virtual machines communicating with each destination
- Processes responsible for the connections
- Destination ports
- Geographic locations of external destinations

Common Microsoft traffic is filtered out to reduce noise and make unusual outbound connections easier to investigate.

---

### 3. Data Exfiltration 📤

**Location:** `Workbook-3-Data-Exfiltration/`

This workbook investigates outbound data movement from the virtual network to external destinations.

It provides visibility into:
- External destination IP addresses
- Amount of outbound data transferred
- Internal virtual machines sending data
- Destination ports
- Geographic locations of external destinations

This can help identify unusual outbound data transfers that may require further investigation for potential data exfiltration.

---

### 4. Threat Intelligence 🚨

**Location:** `Workbook-4-Threat-Intelligence/`

This workbook compares inbound network traffic to the virtual network against threat intelligence indicators in Microsoft Sentinel.

It provides visibility into:
- Known malicious or suspicious IP addresses communicating with the virtual network
- Allowed connections from known malicious IP addresses
- Virtual machines targeted by those IP addresses
- Geographic origin of the suspicious traffic
- Network ports targeted

This can help identify known suspicious IP addresses that were allowed to connect to the virtual network.
