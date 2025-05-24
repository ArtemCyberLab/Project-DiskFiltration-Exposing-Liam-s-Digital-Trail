The goal of this project was to conduct a forensic analysis on a compromised machine to identify the insider threat activity performed by a user named Liam. This included tracking down data exfiltration attempts via USB devices, uncovering the attacker’s methods of evading detection, and extracting hidden indicators of compromise (IOCs) using registry and disk artifacts.

The challenge was based on a pre-configured digital forensics lab environment where I was provided with a disk image (“Disk For Analysis”) and a set of forensic tools. My task was to identify key evidence that exposed Liam’s intentions and the external collaborator who assisted him.

Investigation Process and Findings
1. USB Device Serial Number
Using Autopsy, I analyzed the parsed SYSTEM hive under the USBSTOR key. This revealed the USB device Liam used during the operation.
🡺 Serial Number: 26519******

2. Wi-Fi Hotspot Used to Evade Detection
Within the SOFTWARE hive, I inspected the NetworkList\Profiles registry key and found that Liam connected through a personal mobile hotspot.
🡺 Profile Name: Liam's *****

3. Exfiltration File Copied from USB
By reviewing “Recent Documents” and browsing through the Desktop of the Administrator account, I found the ZIP archive Liam used for exfiltration instructions.
🡺 File Name: Shadow_******

4. Password for ZIP File
Inside the Documents folder, a file named Pass.txt stored the password used to extract the ZIP archive.
🡺 Password: Qwert*****

5. Identity of the External Collaborator
After unzipping the archive and analyzing the PDF with exiftool, I found metadata revealing the author of the instructions.
🡺 Author: ****

6. Correct Extension of Hidden File
The archive included a file without extension. Running exiftool identified it as an image.
🡺 Extension: ***

7. File Searches Performed by Liam
Using the NTUSER.DAT hive of the Administrator, I extracted values from the WordWheelQuery key, which logs Explorer search queries.
🡺 Keywords: Financial, ****

8. Folders Accessed on the USB
From the “Recent Documents” and ShellBags artifacts, I identified folders accessed directly from the USB drive.
🡺 Folder Names (Alphabetical): Critical Data TECH THM, Exfiltration Plan

9. Execution of file_uploader.exe
Autopsy's pre-parsed Prefetch files showed the exact timestamp and execution count of a suspicious binary executed as part of the exfiltration.
🡺 Last Execution Time and Count: 2025-01-29 11:26:*****

10. Hidden Flag
The image inside the ZIP archive contained a hidden comment in its metadata.
🡺 Flag: FLAGT{THM_******

11. File Deletion Event
By exporting and parsing the $UsnJrnl file with MFTECmd.exe, I determined when Liam deleted a sensitive document.
🡺 Deletion Timestamp: 2025-01-29 *****

12. Social Media Distraction Tactic
Browser history indicated that Liam accessed a social media platform, possibly to appear normal.
🡺 URL: https://www*******

13. PowerShell Execution
Analyzing ConsoleHost_history.txt, I found Liam’s final PowerShell command, which aligns with the plan described in the PDF.
🡺 Command Executed:
Get-WmiObject -Class Win32_Share | Select-Object Name, Path

Conclusion
This investigation confirmed that Liam used a USB device (serial: 2651931097993496666) and a personal hotspot (Liam's Iphone) to bypass network monitoring. He copied a ZIP archive (Shadow_Plan.zip) containing instructions and a malicious tool (file_uploader.exe) which he executed twice.

The operation was directed by an external actor named Henry, whose identity was embedded in the PDF metadata. Evidence such as file searches (Financial, Revenue), folder access, and PowerShell usage confirmed that Liam actively gathered and prepared sensitive information for exfiltration. The hidden flag FLAGT{THM_TECH_DATA} further validated this conclusion.

The entire analysis was performed using registry hives, browser artifacts, recent document history, and metadata extraction tools, reinforcing the importance of endpoint-level forensics in detecting insider threats.
