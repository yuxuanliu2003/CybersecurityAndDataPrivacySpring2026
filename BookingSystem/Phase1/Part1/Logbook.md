## 04.02.2026 – Phase 1 Web Security Testing

**Activity:**  
- Performed black-box security testing against the booking system web application running on http://localhost:8001.

**Tools used:**  
- Browser (manual testing)  
- OWASP ZAP (automated baseline scan)

**My work:**  
- Tested registration form input validation  
- Tested long password input (>2000 characters)  
- Observed server error handling behavior  
- Performed automated vulnerability scan using OWASP ZAP  

**Findings:**  
- Input length is not properly limited, causing server-side errors.
- The application blocks certain characters (e.g. '<', SQL keywords) in the email field.
- After submitting the registration form, the application redirects back to the registration page without displaying any success or error message.

**Time spent:**  
- 5 hours
