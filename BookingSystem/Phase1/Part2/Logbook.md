## 11.02-1.3.2026 – Phase 1 Part 2 Retesting

**Activity:**  
- Deployed updated version of the booking system.
- Re-tested previously discovered vulnerabilities.
- Performed second OWASP ZAP scan.
- Created discussion post reporting findings and fixes.

**Tools Used:**  
- Browser manual testing  
- Docker  
- OWASP ZAP  

**Summary:**  
All major vulnerabilities from Part 1 were verified and found to be fixed. Input validation and security handling were significantly improved.


**What I did:**  
- Re-deployed the updated application environment.  
- Tested registration functionality using valid and invalid inputs.  
- Performed SQL injection, XSS, weak password, long input, and malformed email tests.  
- Verified whether previously identified vulnerabilities were fixed.  
- Conducted OWASP ZAP baseline scan and generated a new Markdown report (zap_report_round2.md).  

**Findings:**  
- Invalid email formats and SQL injection style inputs were still accepted by the backend.  
- Server-side input validation remains weak.  
- Registration feedback messages are still unclear.  
- Several security issues identified in Part 1 remain unresolved.  

**Time Spent:**  
- 18 hours
