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

| ID | Severity | Finding | Description | Status | Evidence / Proof |
|------|-----------|----------|--------------|------------------|-----------------|
| 1 | 🟠 Medium | Provide clear success and error messages after user registration attempts | Registration succeeded, but weak password failed | Fixed | Screenshot 1-2 |
| 2 | 🔴 High | Improve server-side validation error handling and feedback | Invalid email register failed. | Fixed | Screenshot 3 |
| 3 | 🔴 High | Log and differentiate failed and successful registration attempts | Registration was successful after entering more than 2000 characters. | Fixed | Screenshot 4 |
| 4 | 🔴 High | Review input validation consistency between frontend and backend | After the front-end inputs `<script>alert(1)</script>`, it redirects to the error interface with status 200. The back-end registers an invalid email address and returns a status code of 200. | Fixed | Screenshot 5-6 |
| 5 | 🔴 High | Perform a full security review of authentication-related endpoints | SQL Injection: test'--@a.com -> succeeded | Fixed | Screenshot 7 |
---

# Screenshots
> ## Screenshot 1
> <img width="803" height="386" alt="image" src="https://github.com/user-attachments/assets/e8289d31-8fe9-40f0-9f13-2816c3a8f137" />

> ## Screenshot 2
> <img width="771" height="390" alt="image" src="https://github.com/user-attachments/assets/f292ad21-8df1-424d-a2c7-df5229c57173" />


> ## Screenshot 3
> <img width="789" height="387" alt="image" src="https://github.com/user-attachments/assets/e3e8b6b6-b094-407c-b696-37861e9cdc98" />



> ## Screenshot 4
> <img width="762" height="349" alt="image" src="https://github.com/user-attachments/assets/bd83ec95-897d-4d55-8147-6394748f4c5f" />


> ## Screenshot 5
> <img width="2088" height="720" alt="image" src="https://github.com/user-attachments/assets/d552e007-721d-424d-8863-b8e3d544b5d1" />


> ## Screenshot 6
> <img width="2088" height="720" alt="image" src="https://github.com/user-attachments/assets/d8a54e05-fbe8-49c2-bd1a-0b5a625b005f" />


> ## Screenshot 7
> <img width="2050" height="899" alt="image" src="https://github.com/user-attachments/assets/755e6a3e-4b56-4309-a57c-fd8ac98510b5" />

---

**Conclusion:**  
Most security vulnerabilities discovered in Part 1 have been fixed. Input validation, filtering, and error handling have been significantly improved.

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
   zap-cli report -o zap_report_round2.md -f markdown
   ```
3. Save the report as `zap_report_round2.md` and link it below.

---
> [!NOTE]
> 📁 **Attach full report:** → `check itslearning` → **Add a link here**

---
