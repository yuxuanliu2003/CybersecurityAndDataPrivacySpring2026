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
- Start:  11.02.2026
- End:  11.02.2026
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

| ID | Severity | Finding | Description | Evidence / Proof |
|------|-----------|----------|--------------|------------------|
| F-01 | 🟠 Medium | Missing registration feedback | After submitting the registration form, the application redirects back to the registration page without displaying any success or error message. | HTTP 302 response observed in browser developer tools |
| F-02 | 🟡 Low | Unclear input validation rules | The application blocks certain characters (e.g. '<', SQL keywords) in the email field. | Browser validation messages and repeated 302 redirects |
| F-03 | 🟡 Low | Improper handling of long password input | Submitting a password exceeding 2000 characters causes an error without a clear explanation. The application does not inform users of password length limits, and server-side handling of oversized input cannot be verified. | Manual testing with long password input (>2000 characters) |
---



> [!NOTE]
> Include up to 5 findings total.   
> Keep each description short and clear.

---

# 5️⃣ OWASP ZAP Test Report (Attachment)

**Purpose:**  
- OWASP ZAP was used to perform an automated security scan against the registration endpoint to identify common web vulnerabilities.

📎 **Attached report:**  
- zap_report_round2.md (https://github.com/yuxuanliu2003/CybersecurityAndDataPrivacySpring2026/blob/0ae9052b8002abda2bd782f06becde63ebc85470/BookingSystem/Phase1/Part2/zap_report_round2.md)


---

**Instructions (CMD version):**
1. Run OWASP ZAP baseline scan:  
   ```bash
   zap-baseline.py -t https://example.com -r zap_report_round1.html -J zap_report.json
   ```
2. Export results to markdown:  
   ```bash
   zap-cli report -o zap_report_round1.md -f markdown
   ```
3. Save the report as `zap_report_round2.md` and link it below.

---
> [!NOTE]
> 📁 **Attach full report:** → `check itslearning` → **Add a link here**

---
