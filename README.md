# SIEM Detection Rules & Use Cases

![SIEM](https://img.shields.io/badge/SIEM-Splunk%20%7C%20Elastic-blue)
![Security](https://img.shields.io/badge/Security-SOC-red)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-orange)

A comprehensive collection of custom SIEM detection rules, use cases, and Sigma rules designed for threat detection and SOC operations. This repository includes Splunk queries, log analysis techniques, and MITRE ATT&CK framework mappings.

## 🔍 Overview

This project demonstrates practical SIEM implementation skills including:
- Custom detection rule development
- Threat hunting queries
- Log correlation and analysis
- MITRE ATT&CK technique mapping
- False positive reduction strategies
- Alert prioritization frameworks

## 🛠️ Technologies Used

- **SIEM Platforms**: Splunk, Elastic Stack (ELK)
- **Rule Formats**: Sigma, Splunk SPL, KQL
- **Frameworks**: MITRE ATT&CK, Cyber Kill Chain
- **Log Sources**: Windows Event Logs, Syslog, Firewall logs, IDS/IPS

## 📚 Detection Use Cases

### 1. Brute Force Attack Detection
**MITRE ATT&CK**: T1110 - Brute Force

```spl
# Splunk Query - Multiple Failed Login Attempts
index=security sourcetype="WinEventLog:Security" EventCode=4625
| stats count by src_ip, user
| where count > 5
| eval severity="HIGH"
| table _time, src_ip, user, count, severity
```

**Logic**: Detects 5+ failed login attempts from same IP within timeframe

---

### 2. Lateral Movement Detection
**MITRE ATT&CK**: T1021 - Remote Services

```spl
# Splunk Query - Unusual RDP Connections
index=security EventCode=4624 Logon_Type=10
| stats dc(dest) as unique_hosts by src_user
| where unique_hosts > 3
| eval alert="Potential Lateral Movement"
```

**Logic**: Identifies users connecting to multiple systems via RDP

---

### 3. Data Exfiltration Detection
**MITRE ATT&CK**: T1048 - Exfiltration Over Alternative Protocol

```spl
# Splunk Query - Large Outbound Data Transfer
index=network sourcetype=firewall action=allowed
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| where total_bytes > 1073741824
| eval total_gb=round(total_bytes/1073741824,2)
| table _time, src_ip, dest_ip, total_gb
```

**Logic**: Alerts on outbound transfers exceeding 1GB

---

### 4. Suspicious PowerShell Execution
**MITRE ATT&CK**: T1059.001 - PowerShell

```spl
# Splunk Query - Encoded PowerShell Commands
index=windows EventCode=4104
| search ("EncodedCommand" OR "-enc" OR "FromBase64String")
| rex field=ScriptBlockText "(?<encoded_command>-enc\s+\S+)"
| table _time, Computer, User, ScriptBlockText
```

**Logic**: Detects obfuscated/encoded PowerShell execution

---

### 5. Privilege Escalation Attempts
**MITRE ATT&CK**: T1068 - Exploitation for Privilege Escalation

```spl
# Splunk Query - Admin Group Modifications
index=security (EventCode=4728 OR EventCode=4732)
| search Group_Name="Administrators"
| table _time, user, src_user, Group_Name, action
```

**Logic**: Monitors additions to administrative groups

---

## 💡 Sigma Rules

### Suspicious Process Creation

```yaml
title: Suspicious cmd.exe Execution
status: experimental
description: Detects suspicious cmd.exe execution patterns
author: Manoj Kumar Arella
date: 2025/11/21
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith: '\cmd.exe'
    CommandLine|contains:
      - '/c'
      - 'whoami'
      - 'net user'
      - 'ipconfig'
  condition: selection
falsepositives:
  - Administrative scripts
  - System maintenance
level: medium
tags:
  - attack.execution
  - attack.t1059.003
```

---

## 👁️ Threat Hunting Queries

### Hunt for Credential Dumping
```spl
index=windows (process_name=lsass.exe OR process_name=mimikatz.exe)
| stats count by host, user, process_name
| where count > 0
```

### Hunt for Suspicious Network Connections
```spl
index=network dest_port IN (4444, 5555, 8080, 31337)
| stats count by src_ip, dest_ip, dest_port
```

---

## 📊 Alert Prioritization Matrix

| Severity | CVSS Score | Response Time | Examples |
|----------|------------|---------------|----------|
| **Critical** | 9.0-10.0 | < 15 min | Ransomware, Data breach |
| **High** | 7.0-8.9 | < 1 hour | Lateral movement, Privilege escalation |
| **Medium** | 4.0-6.9 | < 4 hours | Suspicious process, Policy violation |
| **Low** | 0.1-3.9 | < 24 hours | Informational alerts |

---

## 🛡️ False Positive Reduction

### Whitelisting Strategies

1. **Known Service Accounts**: Exclude automated processes
2. **Approved Tools**: Whitelist legitimate admin tools
3. **Business Hours**: Adjust thresholds based on time
4. **Asset Criticality**: Prioritize alerts from critical systems

### Tuning Example
```spl
# Exclude known good IPs from brute force alerts
index=security EventCode=4625
| search NOT src_ip IN ("10.0.0.100", "10.0.0.101")
| stats count by src_ip, user
| where count > 5
```

---

## 📈 Project Structure

```
SIEM-Detection-Rules/
├── README.md
├── splunk-queries/
│   ├── authentication.spl
│   ├── network-security.spl
│   └── endpoint-detection.spl
├── sigma-rules/
│   ├── process-creation/
│   ├── network-connection/
│   └── file-event/
├── use-cases/
│   ├── lateral-movement.md
│   ├── data-exfiltration.md
│   └── privilege-escalation.md
└── mitre-mapping/
    └── attack-coverage.csv
```

---

## 🎯 Key Features

✅ **30+ Detection Rules** covering common attack techniques
✅ **MITRE ATT&CK Mapping** for all detection use cases
✅ **Multi-Platform Support** (Splunk, Elastic, Sentinel)
✅ **Threat Hunting Queries** for proactive security
✅ **False Positive Tuning** guidelines and examples
✅ **Real-World Use Cases** based on SOC experience

---

## 🚀 How to Use

1. **Choose Your SIEM Platform**: Select queries for Splunk, Elastic, or convert using Sigma
2. **Customize Indexes**: Update index names to match your environment
3. **Adjust Thresholds**: Tune detection thresholds based on your baseline
4. **Test & Validate**: Run queries in test environment before production
5. **Monitor & Refine**: Continuously improve based on false positives

---

## 📝 Best Practices

- **Baseline Your Environment**: Understand normal behavior first
- **Start with High-Fidelity Rules**: Focus on low false-positive detections
- **Document Everything**: Maintain clear runbooks for each alert
- **Correlate Multiple Sources**: Combine logs from different systems
- **Regular Review**: Update rules based on new threat intelligence

---

## 🔗 References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules Repository](https://github.com/SigmaHQ/sigma)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)
- [Elastic Security Rules](https://github.com/elastic/detection-rules)

---

## 💬 Contact

**Manoj Kumar Arella**
- LinkedIn: [Manoj Kumar](https://www.linkedin.com/in/manoj-kumar-b6a804173)
- Email: Arellamanojkumar1997@gmail.com

---

## 📝 License

This project is open source and available for educational and professional use.

---

*Built with expertise from 2+ years of hands-on experience in SOC operations and threat detection.*
