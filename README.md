# Goal
To detect attempts by adversaries to bypass User Access Control (UAC) mechanisms on Windows systems.

# Categorization
This technique is categorized as Privilege Escalation and Defense Evasion within the MITRE ATT&CK framework.

# Strategy Abstract
In order to detect this technqiue a YARA rule will be made to detect specific patterns in files or processes, including PowerShell scripts or text files containing the Powershell logs. 

# Technical Content
Windows User Account Control (UAC) permits a program to increase its privileges in order to execute a task with higher level permissions. One way a system might do this is to prompt a user for confirmation, such as through a popup on the system.

Adversaries may attempt to bypass or manipulate UAC mechanisms in order to escalate their prviledge without the need for a password or without the UAC popup showing on the machine.

The specific UAC bypass technqiue we are looking to detect is one that uses PowerShell code to bypass User Account Control using the Windows 10 Features on Demand Helper (fodhelper.exe)

```
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Users\User\Desktop\123.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```

# Blind Spots and Asssumptions
This strategy relies on the following assumptions:

* The ADS assumes that PowerShell logging is enabled and configured appropriately on monitored systems. If PowerShell logging is disabled or logs are not centrally collected, the ADS may not have sufficient visibility to detect UAC bypass attempts

A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert:

* If adversaries employ fileless UAC bypass techniques that do not involve executing external binaries like fodhelper.exe, the ADS may not detect these attempts.
* Adversaries may obfuscate PowerShell commands to evade detection by the ADS, potentially bypassing its monitoring capabilities

# False Positives
Legitimate administrative tasks involving the creation of the specified registry key and execution of fodhelper.exe may trigger false positives.

# Priority
High: Any attempt to bypass UAC poses a significant security risk and warrants immediate investigation.

# Validation

```
rule detect_UAC_bypass {
    strings:
        $exe_binary = "C:\\Windows\\System32\\fodhelper.exe"
        $reg_key = "HKCU:\\software\\classes\\ms-settings\\shell\\open\\command"
        $cmd_content = "New-Item"
        $ps_content = "Start-Process"
    condition:
        all of ($cmd_content, $ps_content, $exe_binary, $reg_key)
}
```

# Response
* Investigate the system where the alert fired to determine the legitimacy of the activity.
* Identify the source of the PowerShell commands and assess the intent behind the UAC bypass attempt.
* Remediate any unauthorized activity and strengthen security controls to prevent future bypass attempts.


# Additional Resources
