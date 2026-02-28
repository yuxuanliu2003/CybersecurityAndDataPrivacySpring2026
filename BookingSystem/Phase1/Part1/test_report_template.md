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
- Start:  03.02.2026
- End:  04.02.2026
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
| 1 | 🟠 Medium | Provide clear success and error messages after user registration attempts | Registration succeeded. After registration, refreshing the page yields no response. | Screenshot 1 |
| 2 | 🔴 High | Improve server-side validation error handling and feedback | Empty input is not allowed, but illegal email addresses can be registered. | Screenshot 2-3 |
| 3 | 🔴 High | Log and differentiate failed and successful registration attempts | Registration error due to inputting more than 2000 characters | Screenshot 4 |
| 4 | 🔴 High | Review input validation consistency between frontend and backend | After the front-end inputs `<script>alert(1)</script>`, it redirects to the error interface with status 200. The back-end registers an invalid email address and returns a status code of 200. | Screenshot 5-6 |
| 5 | 🔴 High | Perform a full security review of authentication-related endpoints | SQL Injection: ' OR '1'='1 | Screenshot 7 |
---

# Screenshots
> ## Screenshot 1
> <img width="708" height="331" alt="image" src="https://github.com/user-attachments/assets/ecf2b992-cce4-4edd-886b-e59201f69a0f" />


> ## Screenshot 2
> <img width="800" height="343" alt="image" src="https://github.com/user-attachments/assets/d7e6b55b-f4a9-43ad-a919-c8fd42487489" />

> ## Screenshot 3
> <img width="771" height="262" alt="image" src="https://github.com/user-attachments/assets/34277c00-9de4-4a35-b2d2-69acc7443741" />

> ## Screenshot 4
> <img width="481" height="259" alt="image" src="https://github.com/user-attachments/assets/72366e69-f20b-4e1c-bbe3-ca3a5d56d49b" />


> ## Screenshot 5
> <img width="2268" height="715" alt="image" src="https://github.com/user-attachments/assets/6a1911ce-36bf-4aea-9414-c8c76c304bc2" />

> ## Screenshot 6
> <img width="831" height="462" alt="image" src="https://github.com/user-attachments/assets/8c884e09-a285-4dc3-bf27-33e2ae8358dd" />

> ## Screenshot 7
> <img width="2322" height="713" alt="image" src="https://github.com/user-attachments/assets/7038524b-0a02-4ca4-ad27-9abe52183285" />


> [!NOTE]
> Include up to 5 findings total.   
> Keep each description short and clear.

---

# 5️⃣ OWASP ZAP Test Report (Attachment)

**Purpose:**  
- OWASP ZAP was used to perform an automated security scan against the registration endpoint to identify common web vulnerabilities.

📎 **Attached report:**  
- zap_report_round1.md　https://github.com/yuxuanliu2003/CybersecurityAndDataPrivacySpring2026/blob/0d0adc5d95cdb718f9b494ccd0d92dbfd85a70a3/BookingSystem/Phase1/Part1/zap_report_round1.md


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
3. Save the report as `zap_report_round1.md` and link it below.

---
> [!NOTE]
> 📁 **Attach full report:** → `check itslearning` → **Add a link here**

---
