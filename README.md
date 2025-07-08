# 🛡️ Bug Bounty Bug Types & Examples

> Comprehensive list of bug types with examples for penetration testing and bug bounty hunting.

---

## 🔐 Injection

- **SQL Injection (SQLi)**  
  `Example:` `' OR '1'='1`  
  `CWE-89`

- **Command Injection**  
  `Example:` `; ls -la`  
  `CWE-77`

- **LDAP Injection**  
  `Example:` `*)(uid=*))(|(uid=*`  
  `CWE-90`

- **XPath Injection**  
  `Example:` `admin' or '1'='1`  
  `CWE-643`

- **XML Injection / XXE**  
  `Example:` `<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`  
  `CWE-611`

- **NoSQL Injection**  
  `Example:` `{ "$ne": null }`  
  `CWE-943`

- **Template Injection**  
  `Example:` `{{7*7}}` in Jinja2  
  `CWE-1336`

- **Host Header Injection**  
  `Example:` `Host: evil.com`  
  Used in password reset poisoning

- **HTTP Response Splitting**  
  `Example:` `\r\nSet-Cookie: evil=1`

---

## 🧠 Cross-Site Issues

- **Reflected XSS**  
  `Example:` `"><script>alert(1)</script>`  
  `CWE-79`

- **Stored XSS**  
  `Example:` Comment field saves `<script>alert(1)</script>`

- **DOM-based XSS**  
  `Example:` Using `location.hash` unsanitized

- **CSRF (Cross-Site Request Forgery)**  
  `Example:` Auto-submitting POST request to change email  
  `CWE-352`

- **XSSI (Cross-Site Script Inclusion)**  
  `Example:` Loading JSON using `<script src="">`

- **Clickjacking**  
  `Example:` Iframe tricks user into clicking

- **Web Cache Deception**  
  `Example:` Accessing `/account.jpg%20` caches sensitive data

---

## 🔑 Authentication & Session

- **Broken Authentication**  
  `Example:` Default creds like `admin/admin`  
  `CWE-287`

- **Session Fixation**  
  `Example:` Sharing `JSESSIONID` between users  
  `CWE-384`

- **Session Hijacking**  
  `Example:` Stealing cookies via XSS

- **JWT Misconfiguration**  
  `Example:` Changing `alg` to `none` in token  
  `CWE-345`

- **Credential Stuffing / Brute Force**  
  `Example:` Trying 1000 common passwords

- **Password Reset Poisoning**  
  `Example:` Manipulating Host header for reset URL

- **OAuth Token Leakage**  
  `Example:` Leaking access token in Referer header

---

## 🔓 Access Control

- **IDOR (Insecure Direct Object Reference)**  
  `Example:` Accessing `/user/124` instead of `/user/123`  
  `CWE-639`

- **Vertical Privilege Escalation**  
  `Example:` Regular user changes role to `admin`

- **Horizontal Privilege Escalation**  
  `Example:` Accessing peer's profile or invoice

- **Mass Assignment**  
  `Example:` Sending `is_admin=true` in JSON body  
  `CWE-915`

- **Forceful Browsing**  
  `Example:` Direct access to restricted URLs

---

## ⚙️ Security Misconfigurations

- **Directory Listing**  
  `Example:` `/uploads/` exposes file list

- **Exposed Admin Panel**  
  `Example:` `/admin/` accessible without auth

- **Exposed Files (.env, .git, .bak, .zip)**  
  `Example:` Accessing `.env` reveals credentials

- **CORS Misconfiguration**  
  `Example:` Wildcard (`*`) allows any origin  
  `CWE-942`

- **Improper Rate Limiting**  
  `Example:` OTP brute-force without blocking

- **Verbose Error Messages**  
  `Example:` Stack traces shown on frontend

- **Missing Security Headers**  
  `Example:` No `CSP`, `X-Frame-Options`, `X-Content-Type-Options`

---

## 🧪 Business Logic Issues

- **Coupon Abuse**  
  `Example:` Reusing discount codes infinitely

- **Payment Bypass**  
  `Example:` Changing price in client-side request

- **Referral Abuse**  
  `Example:` Referring yourself with fake emails

- **Race Condition**  
  `Example:` Submitting requests in parallel to double credits

- **Inventory Manipulation**  
  `Example:` Ordering with negative quantity

- **Authorization Logic Flaws**  
  `Example:` Cancelled orders still processed

---

## 📡 API Vulnerabilities

- **BOLA (Broken Object Level Auth)**  
  `Example:` Changing `userId` in GraphQL query

- **Mass Assignment in API**  
  `Example:` Sending `role=admin` in JSON POST

- **Rate Limit Bypass**  
  `Example:` Rotating IPs to avoid lockout

- **Improper HTTP Methods**  
  `Example:` `PUT`/`DELETE` enabled without checks

- **Introspection Enabled (GraphQL)**  
  `Example:` Access to full schema and queries

- **Missing Auth Checks**  
  `Example:` Unauthenticated access to admin APIs

---

## 📲 Mobile App Vulnerabilities

- **Hardcoded Secrets in APK**  
  `Example:` API keys or tokens in strings.xml

- **Insecure Storage**  
  `Example:` Storing passwords in SQLite without encryption

- **Root Detection Bypass**  
  `Example:` App runs on rooted/jailbroken device

- **SSL Pinning Bypass**  
  `Example:` Using Frida or objection to MITM SSL

- **Insecure WebView Usage**  
  `Example:` `webview.loadUrl()` allows `javascript:` URLs

- **Improper Certificate Validation**  
  `Example:` `TrustManager` accepts all certs

---

## 📦 Server-Side Vulnerabilities

- **SSRF (Server-Side Request Forgery)**  
  `Example:` `url=http://localhost:8080`

- **RCE (Remote Code Execution)**  
  `Example:` File upload → code execution

- **Path Traversal**  
  `Example:` `../../etc/passwd`  
  `CWE-22`

- **File Upload Vulnerabilities**  
  `Example:` Uploading `.php` shell bypassing validation

- **Insecure Deserialization**  
  `Example:` Java object triggers command execution

- **Log Injection / Forging**  
  `Example:` Adding line breaks to pollute server logs

- **WebSocket Abuse**  
  `Example:` No origin check → CSRF via WebSocket

---

## 🌍 Other Vulnerabilities

- **Subdomain Takeover**  
  `Example:` Unused subdomain points to unclaimed S3 bucket

- **Clickjacking**  
  `Example:` Hidden iframe tricks user interaction

- **Open Redirect**  
  `Example:` `?next=https://evil.com`  
  `CWE-601`

- **OAuth Misconfiguration**  
  `Example:` Accepting tokens from any client

- **SAML/SSO Flaws**  
  `Example:` Modifying SAML assertions for auth bypass

- **Typosquatting / Homograph Attacks**  
  `Example:` `xn--example-9d0.com` (IDN spoofing)

- **Broken Cryptography**  
  `Example:` Using ECB mode or hardcoded keys

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org)
- [Bug Bounty Guide – HackerOne](https://www.hackerone.com/resources)

---
