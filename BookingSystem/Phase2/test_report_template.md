# 1️⃣ Introduction

**Tester(s):**  
- Name:  Yuxuan Liu

**Purpose:**  
- The purpose of this test is to identify functional issues and security vulnerabilities in the booking system registration functionality.

**Scope:**  
- Tested components:  User registration page (/register) 
- Exclusions:  Login, booking management, admin features 
- Test approach: Black-box

**Test environment & dates:**  
- Start:  17.02.2026
- End:  18.02.2026 (+ 27.2-1.3)
- Test environment details (OS, runtime, DB, browsers):
  - OS: Windows 11  
  - Runtime: Docker Desktop  
  - Database: PostgreSQL (Docker container)  
  - Browser: Google Chrome

**Assumptions & constraints:**  
- Testing was performed on a local Docker-based environment provided by the course.  
- No access to application source code or backend logs.  
- Testing time was limited.

---

# 2️⃣ Executive Summary

**Short summary (1-2 sentences):**  The registration functionality of the booking system was tested for functional correctness and common security issues. Several issues were identified related to missing user feedback and unclear server-side validation behavior.

**Overall risk level:**  Medium 

**Top 5 immediate actions:**  
1. Provide clear success and error messages after user registration attempts.  
2. Improve server-side validation error handling and feedback.  
3. Log and differentiate failed and successful registration attempts.  
4. Review input validation consistency between frontend and backend.  
5. Perform a full security review of authentication-related endpoints. 

---

# 3️⃣ Severity scale & definitions

|  **Severity Level**  | **Description**                                                                                                              | **Recommended Action**           |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
|      🔴 **High**     | A serious vulnerability that can lead to full system compromise or data breach (e.g., SQL Injection, Remote Code Execution). | *Immediate fix required*         |
|     🟠 **Medium**    | A significant issue that may require specific conditions or user interaction (e.g., XSS, CSRF).                              | *Fix ASAP*                       |
|      🟡 **Low**      | A minor issue or configuration weakness (e.g., server version disclosure).                                                   | *Fix soon*                       |
| 🔵 **Info** | No direct risk, but useful for system hardening (e.g., missing security headers).                                            | *Monitor and fix in maintenance* |


---

# 4️⃣ Findings (filled with examples → replace)

> Fill in one row per finding. Focus on clarity and the most important issues.

| ID | Severity | Finding | Description | Status | Evidence / Proof |
|------|-----------|----------|--------------|------------------|-----------------|
| 1 | 🟠 Medium | Provide clear success and error messages after user registration attempts | Registration succeeded, but weak password failed | Fixed | Screenshot 1-2 |
| 2 | 🔴 High | Improve server-side validation error handling and feedback | Invalid email register failed. | Fixed | Screenshot 2-3 |
| 3 | 🔴 High | Log and differentiate failed and successful registration attempts | Invalid email register failed. Registration was successful after entering more than 2000 characters. | Fixed | Screenshot 3-4 |
| 4 | 🔴 High | Review input validation consistency between frontend and backend | Encoded malicious input (e.g., test%2Ftest@test.com) bypassed frontend validation and was accepted by the backend. I changed the HTML input type="email" for the email input box to input type="text", registration faild. | Not Fixed | Screenshot 5-6 |
| 5 | 🔴 High | Perform a full security review of authentication-related endpoints | SQL injection style input such as test'/*@test.com was accepted, indicating serious backend security weaknesses. | Not Fixed | Screenshot 7 |
---

# Screenshots
> ## Screenshot 1
> <img width="774" height="355" alt="image" src="https://github.com/user-attachments/assets/1d959df4-6b73-4e09-9d63-fbc852a38d28" />


> ## Screenshot 2
> <img width="740" height="382" alt="image" src="https://github.com/user-attachments/assets/774e2fdf-57d2-4b50-ab13-334d4c8e7742" />




> ## Screenshot 3
> <img width="766" height="385" alt="image" src="https://github.com/user-attachments/assets/0ddc3843-4555-4649-a801-9e1c9aff2668" />



> ## Screenshot 4
> <img width="760" height="346" alt="image" src="https://github.com/user-attachments/assets/e0813630-6f18-4131-a424-8caa43f6371f" />



> ## Screenshot 5
> <img width="766" height="354" alt="image" src="https://github.com/user-attachments/assets/51acb058-b4ba-41e2-b644-5b236d6e3073" />

> ## Screenshot 6
> <img width="1894" height="642" alt="image" src="https://github.com/user-attachments/assets/a90ae54c-2045-40ce-9184-d48323ea0b5d" />




> ## Screenshot 7
> <img width="764" height="364" alt="image" src="https://github.com/user-attachments/assets/db028628-49c4-478a-b73e-9c49f60f236d" />





---

**Conclusion:**  
Most security vulnerabilities discovered in Part 1 have been fixed. Input validation, filtering, and error handling have been significantly improved.

> [!NOTE]
> Include up to 5 findings total.   
> Keep each description short and clear.

---

# Cracked Password Report

## Environment

Operating System: Linux (Docker container)

Tool: Hashcat v6.2.6

Wordlist: rockyou.txt

Attack Mode: Dictionary attack

Hash Type: MD5

## Cracked Password

1. User: whatsupdoc@looneytunes.tv 
   Hash: a0e8402fe185455606a2ae870dcbc4cd (MD5)
   Password: carrots123
   Evidence/Proof: <img width="767" height="101" alt="image" src="https://github.com/user-attachments/assets/0c0fa06e-2480-4607-8d0d-466efcb76a7b" />
                   <img width="765" height="356" alt="image" src="https://github.com/user-attachments/assets/5c9e67dc-7423-4c83-881b-f025edac8492" />



2. User: doh@springfieldpower.net 
   Hash: d730fc82effd704296b5bbcff45f323e (MD5)
   Password: donuts4life
   Evidence/Proof: <img width="759" height="71" alt="image" src="https://github.com/user-attachments/assets/7929f532-b31c-452a-a3d7-09159ba8ed41" />
                   <img width="771" height="361" alt="image" src="https://github.com/user-attachments/assets/a5a008dd-7d23-43a3-96a9-53b06a553b3a" />



3. User: darkknight@gothamwatch.org 
   Hash: 735f7f5e652d7697723893e1a5c04d90 (MD5)
   Password: iamvengeance
   Method: Rule-based attack
   Explanation: According to the hint, the first six letters were "iamven". Based on Batman's famous phrase "I am vengeance", the full password was derived.
   Evidence/Proof: <img width="786" height="357" alt="image" src="https://github.com/user-attachments/assets/9c54dd8d-718b-4a1b-b02b-bdf6eea7a632" />



5. User: iamyourfather@deathstar.gov 
   Hash: 706ab9fc256efabf4cb4cf9d31ddc8eb (MD5)
   Password: darkside42
   Evidence/Proof: <img width="759" height="65" alt="image" src="https://github.com/user-attachments/assets/5ee4acf2-07b3-4d67-a6da-e8ba1e315847" />
                   <img width="771" height="370" alt="image" src="https://github.com/user-attachments/assets/7fe00a3f-116c-4e77-8fcb-b152b359c85a" />


6. genius@starkindustries.com
   Hash: d50ba4dd3fe42e17e9faa9ec29f89708 (MD5)
   Password: iamironman
   Evidence/Proof: <img width="748" height="65" alt="image" src="https://github.com/user-attachments/assets/62cf5206-db59-4436-99cf-5743ad4aff5b" />
                   <img width="760" height="356" alt="image" src="https://github.com/user-attachments/assets/9fe35ef3-45a9-4479-bdc4-f8446db171b7" />



---

# 5️⃣ OWASP ZAP Test Report (Attachment)

**Purpose:**  
- OWASP ZAP was used to perform an automated security scan against the registration endpoint to identify common web vulnerabilities.

📎 **Attached report:**  
- zap_report_round3.md (https://github.com/yuxuanliu2003/CybersecurityAndDataPrivacySpring2026/blob/fba0e35243485cb000e229de96f7b157bde90944/BookingSystem/Phase2/zap_report_round3.md)


---

**Instructions (CMD version):**
1. Run OWASP ZAP baseline scan:  
   ```bash
   zap-baseline.py -t https://example.com -r zap_report_round1.html -J zap_report.json
   ```
2. Export results to markdown:  
   ```bash
   zap-cli report -o zap_report_round3.md -f markdown
   ```
3. Save the report as `zap_report_round3.md` and link it below.

---
> [!NOTE]
> 📁 **Attach full report:** → `check itslearning` → **Add a link here**

---
