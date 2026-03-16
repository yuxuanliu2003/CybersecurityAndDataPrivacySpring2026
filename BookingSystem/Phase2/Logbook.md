# 16.02-18.2.2026 – Phase 2
Debian Docker environment failed, so I switched to using Docker Desktop and VS Code.

**Activity:**  
- Deployed updated version of the booking system.
- Re-tested previously discovered vulnerabilities.
- Performed third OWASP ZAP scan.
- Learning how to crack hashed passwords using Hashcat.

**Tools Used:**  
- Browser manual testing  
- Docker  
- OWASP ZAP 
- Operating System: Linux (Docker container)
- Tool: Hashcat v6.2.6
- Wordlist: rockyou.txt
- Attack Mode: Dictionary attack
- Hash Type: MD5 

**What I did:**  
- Re-deployed the updated application environment.  
- Tested registration functionality using valid and invalid inputs.  
- Performed SQL injection, XSS, weak password, long input, and malformed email tests.  
- Verified whether previously identified vulnerabilities were fixed.  
- Conducted OWASP ZAP baseline scan and generated a new Markdown report (zap_report_round3.md).  

**Findings:**  
- Invalid email formats and SQL injection style inputs were still accepted by the backend.  
- Server-side input validation remains weak.  
- Several security issues identified in Phase 1 remain unresolved.  

**Cracked password steps performed:** 

- Installed Hashcat inside Docker.
- Installed nano for file editing.
- Created a hash file named hash.txt.
- Tried to use rockyou.txt but encountered a missing file error.
- Downloaded the rockyou.txt wordlist.
- Used Hashcat with dictionary attack mode to crack the hash.
- Downloaded rockyou.txt manually using wget.
- Successfully cracked the MD5 hash using dictionary attack.

**Problems encountered:** 

 **The rockyou.txt file was missing.**
- Next steps: Solved by downloading the wordlist from GitHub.

 **Attempted dictionary attack on hash 735f7f5e652d7697723893e1a5c04d90.**
- Result: Unsuccessful; rockyou.txt exhausted
- Analysis: Password may not be in dictionary or hash type may differ
- Next steps: Try rule-based attack

**What I learned:** 

How dictionary attacks work.

How to use Hashcat basic commands.

How weak passwords can be cracked very quickly.

The attack was successful because the password was weak and existed in the rockyou.txt wordlist. Dictionary attacks are effective against common and simple passwords, but they are less effective against long and complex passwords.

This experiment shows that weak passwords are extremely vulnerable to dictionary attacks, emphasizing the importance of strong password policies and secure hashing algorithms in cybersecurity.

**Time Spent:**  
- 14 hours
