# Goal
Detect attempts to bypass User Account Control (UAC) using the fodhelper.exe utility.

# Categorization
This technique is categorized as Privilege Escalation and Defense Evasion within the MITRE ATT&CK framework.

# Strategy Abstract
The strategy aims to identify unauthorized modifications to critical registry keys associated with the fodhelper.exe utility, indicating potential attempts to bypass User Account Control (UAC) restrictions. It leverages Sysmon logs forwarded to Splunk for analysis.

# Technical Content
The fodhelper.exe utility is a legitimate Windows binary used for managing optional features in Windows. Attackers exploit this utility by manipulating specific registry keys to execute arbitrary code with elevated privileges, bypassing UAC restrictions. The alert monitors for changes to the HKCU:\Software\Classes\ms-settings\shell\open\command registry key, commonly abused by attackers for UAC bypass techniques.

Below is an example of powershell commands an adversary might execute in order to bypass the UAC as well as an explanation for what each command is doing.

```
copy C:\Windows\System32\cmd.exe C:\Users\User\Desktop\123.exe
```
This command copies cmd.exe to a seperate folder with a different name, this is done because Windows Defender blocks any call of cmd.exe as a registry value

```
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
```
Here a new registry key is created named "ms-settings\shell\open\command" under the current user's hive (HKCU) in the Windows Registry. The -Force parameter ensures that the command creates the key even if it already exists. This key is commonly targeted because it allows an attacker to associate a custom executable with certain file types or actions.

```
New-ItemProperty -Path "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
```
Next a new registry value is created named DelegateExecute under the ms-settings\shell\open\command registry key. Setting this property to an empty string effectively disables the use of the COM elevation moniker, which is a technique used by Windows to elevate privileges for certain actions.

```
Set-ItemProperty -Path "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Users\User\Desktop\123.exe"
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```
This command sets the value of the default property (default) under the ms-settings\shell\open\command registry key to the path of the previously created 123.exe file. By associating this file with the default command for opening certain types of files, this allows the attacker to launch the 123.exe executable with elevated privileges when fodhelper.exe is started.

```
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```
Finally the fodhelper.exe utility located in the C:\Windows\System32 directory is launched, which would trigger 123.exe to execute with elevated privileges. The -WindowStyle Hidden parameter ensures that the fodhelper utility window is hidden from view when it is executed.


# Blind Spots and Asssumptions
This strategy relies on the following assumptions:

* There is proper functioning of endpoint detection tooling, correct forwarding of logs to Splunk, and successful indexing of logs by the SIEM

A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert:

* If adversaries employ fileless UAC bypass techniques that do not involve modifying Windows Registry keys.
* Adversaries may obfuscate PowerShell commands to evade detection by the ADS, potentially bypassing its monitoring capabilities.

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