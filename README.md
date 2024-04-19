# Goal
Detect attempts to bypass User Account Control (UAC) using the fodhelper.exe utility.

# Categorization
This technique is categorized as Privilege Escalation and Defense Evasion within the MITRE ATT&CK framework.

# Strategy Abstract
The strategy aims to identify unauthorized modifications to critical registry keys associated with the fodhelper.exe utility, indicating potential attempts to bypass User Account Control (UAC) restrictions. It leverages Sysmon logs forwarded to Splunk for analysis.

# Technical Content
The fodhelper.exe utility is a legitimate Windows binary used for managing optional features in Windows. Attackers exploit this utility by manipulating specific registry keys to execute arbitrary code with elevated privileges, bypassing UAC restrictions. The alert monitors for changes to the HKCU:\Software\Classes\ms-settings\shell\open\command registry key, commonly abused by attackers for UAC bypass techniques.

Below is an example of some powershell commands an adversary might execute in order to do this.

```
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Users\User\Desktop\123.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```

# Blind Spots and Asssumptions
This strategy relies on the following assumptions:

* There is proper functioning of endpoint detection tooling, correct forwarding of logs to Splunk, and successful indexing of logs by the SIEM

A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert:

* If adversaries employ fileless UAC bypass techniques that do not involve executing external binaries like fodhelper.exe, the ADS may not detect these attempts.
* Adversaries may obfuscate PowerShell commands to evade detection by the ADS, potentially bypassing its monitoring capabilities

# False Positives
False positives may occur due to legitimate changes by system administrators or software updates that modify the monitored registry key.

# Priority
High: Any attempt to bypass UAC poses a significant security risk and warrants immediate investigation as this means an adversary has already infiltrated the machine.

# Validation
Validation can occur for this technqiue by entering the following query into Splunk.

```
index="main" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject ="HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command"
```

# Response
* Investigate the system where the alert fired to determine the legitimacy of the activity.
* Identify the source of the PowerShell commands and assess the intent behind the UAC bypass attempt.
* Identify what the point of entry for the adversary is and implement containment measures to prevent further compromise


# Additional Resources
“Abuse Elevation Control Mechanism: Bypass User Account Control.” Abuse Elevation Control Mechanism: Bypass User Account Control, Sub-Technique T1548.002 - Enterprise | MITRE ATT&CK®, 30 Jan. 2020, attack.mitre.org/techniques/T1548/002/. 

“Earth Lusca.” Earth Lusca, TAG-22, Group G1006 | MITRE ATT&CK®, 1 July 2022, attack.mitre.org/groups/G1006/. 

Trendmicro, www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf. Accessed 16 Apr. 2024. 

“UAC Bypass - Explanation and Demonstration.” YouTube, YouTube, 2 Sept. 2022, www.youtube.com/watch?v=kDwKlnIH9Ks. 