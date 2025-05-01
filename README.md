# 🛡️ Bug Bounty Bug Types

## 🔐 Injection

- **SQL Injection (SQLi)**  
  `Example:` `' OR '1'='1`

- **Command Injection**  
  `Example:` `; ls -la`

- **LDAP Injection**  
  `Example:` `*)(uid=*))(|(uid=*`

- **XML Injection**  
  `Example:` `<user><name>admin</name></user>`

- **XPath Injection**  
  `Example:` `admin' or '1'='1`

- **NoSQL Injection**  
  `Example:` `{ "$ne": null }`

- **Template Injection**  
  `Example:` `{{7*7}}` in Jinja2

---

## 🧠 Cross-Site Issues

- **Reflected XSS**  
  `Example:` `"><script>alert(1)</script>`

- **Stored XSS**  
  `Example:` A comment field that stores `<script>alert(1)</script>`

- **DOM-based XSS**  
  `Example:` `location.hash` reflecting unsanitized

- **CSRF (Cross-Site Request Forgery)**  
  `Example:` Auto-submitting a POST request to change email/password

- **XSSI (Cross-Site Script Inclusion)**  
  `Example:` Loading JSON via `<script src="">`

---

## 🔑 Authentication & Session

- **Broken Authentication**  
  `Example:` Login with default credentials like `admin/admin`

- **Session Fixation**  
  `Example:` Reusing `JSESSIONID` across users

- **Session Hijacking**  
  `Example:` Stealing cookies via XSS

- **JWT Misconfiguration**  
  `Example:` Changing alg to "none" in JWT

- **Credential Stuffing / Brute Force**  
  `Example:` Trying 1000 common passwords

---

## 🔓 Access Control

- **IDOR**  
  `Example:` Changing `/user/123` to `/user/124`

- **Vertical Privilege Escalation**  
  `Example:` User changes role to `admin`

- **Horizontal Privilege Escalation**  
  `Example:` Accessing another user's data

- **Mass Assignment**  
  `Example:` Sending `is_admin=true` in a request body

---

## ⚙️ Misconfigurations

- **Directory Listing**  
  `Example:` `/uploads/` shows all files

- **Exposed Admin Panel**  
  `Example:` `/admin/` is accessible without auth

- **Exposed .git/.env**  
  `Example:` Accessing `.env` with secrets

- **CORS Misconfiguration**  
  `Example:` Allowing `*` or malicious origins

- **Improper Rate Limiting**  
  `Example:` Brute-forcing OTP without blocking

- **Verbose Error Messages**  
  `Example:` Stack trace reveals server structure

---

## 🧪 Business Logic

- **Coupon Abuse**  
  `Example:` Reusing a promo code infinitely

- **Payment Bypass**  
  `Example:` Modifying payment data client-side

- **Referral Abuse**  
  `Example:` Referring yourself with multiple emails

- **Race Condition**  
  `Example:` Submitting requests simultaneously to double credits

---

## 📡 API Bugs

- **BOLA (Broken Object Level Auth)**  
  `Example:` Changing user ID in GraphQL query

- **Mass Assignment**  
  `Example:` Posting `role: admin` in JSON

- **Rate Limit Bypass**  
  `Example:` Changing IP to bypass OTP limit

- **Improper Access Control**  
  `Example:` API endpoint lacks auth check

---

## 📲 Mobile App Bugs

- **Hardcoded Secrets**  
  `Example:` API key in APK

- **Insecure Storage**  
  `Example:` Storing passwords in plain SQLite DB

- **Root Detection Bypass**  
  `Example:` App runs on rooted device

- **SSL Pinning Bypass**  
  `Example:` Intercept HTTPS using Burp after bypass

- **Insecure WebView**  
  `Example:` WebView allows `javascript:` execution

---

## 📦 Server-Side Issues

- **SSRF**  
  `Example:` `url=http://localhost:8080`

- **RCE**  
  `Example:` File upload leads to code exec

- **Path Traversal**  
  `Example:` `../../etc/passwd`

- **File Upload Vuln**  
  `Example:` Uploading `.php` shell

- **Deserialization Bugs**  
  `Example:` Java serialized object triggers RCE

---

## 🌍 Other

- **Subdomain Takeover**  
  `Example:` Unused subdomain points to unclaimed S3

- **Clickjacking**  
  `Example:` Hidden iframe tricking user clicks

- **Open Redirect**  
  `Example:` `?redirect=https://evil.com`

- **OAuth Misconfig**  
  `Example:` Accepting tokens from any client

- **SAML/SSO Flaws**  
  `Example:` Manipulating SAML assertions

---
