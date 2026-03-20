# Password Cracking Report

## Methodology

The password hashes were cracked using **Hashcat**.

A dictionary-based attack was performed using the widely known `rockyou.txt` wordlist:

    hashcat -m 0 -a 0 hash.txt rockyou.txt

In addition, rule-based and hybrid attacks were applied based on contextual hints provided in the task. Candidate passwords were constructed using common patterns and verified by comparing their MD5 hashes.

---

## Cracked Password

### 1. User: whatsupdoc@looneytunes.tv 
- Hash: a0e8402fe185455606a2ae870dcbc4cd (MD5)
- Password: carrots123
- Method: Dictionary attack
- Explanation: The password was found directly in the rockyou.txt wordlist.
- Evidence/Proof:
  > <img width="767" height="101" alt="image" src="https://github.com/user-attachments/assets/0c0fa06e-2480-4607-8d0d-466efcb76a7b" />
  > <img width="765" height="356" alt="image" src="https://github.com/user-attachments/assets/5c9e67dc-7423-4c83-881b-f025edac8492" />



### 2. User: doh@springfieldpower.net 
- Hash: d730fc82effd704296b5bbcff45f323e (MD5)
- Password: donuts4life
- Method: Dictionary attack
- Explanation: The password was found directly in the rockyou.txt wordlist.
- Evidence/Proof:
  > <img width="759" height="71" alt="image" src="https://github.com/user-attachments/assets/7929f532-b31c-452a-a3d7-09159ba8ed41" />
  > <img width="771" height="361" alt="image" src="https://github.com/user-attachments/assets/a5a008dd-7d23-43a3-96a9-53b06a553b3a" />



### 3. User: darkknight@gothamwatch.org 
- Hash: 735f7f5e652d7697723893e1a5c04d90 (MD5)
- Password: iamvengeance
- Method: Dictionary + rule-based attack
- Explanation: The password was not found directly in the rockyou.txt wordlist. So based on the hint "iamven", the password was derived from the phrase "I am vengeance".
- Evidence/Proof:
  > <img width="786" height="357" alt="image" src="https://github.com/user-attachments/assets/9c54dd8d-718b-4a1b-b02b-bdf6eea7a632" />



### 4. User: iamyourfather@deathstar.gov 
- Hash: 706ab9fc256efabf4cb4cf9d31ddc8eb (MD5)
- Password: darkside42
- Method: Dictionary attack
- Explanation: The password was found directly in the rockyou.txt wordlist.
- Evidence/Proof:
  > <img width="759" height="65" alt="image" src="https://github.com/user-attachments/assets/5ee4acf2-07b3-4d67-a6da-e8ba1e315847" />
  > <img width="771" height="370" alt="image" src="https://github.com/user-attachments/assets/7fe00a3f-116c-4e77-8fcb-b152b359c85a" />


### 5. User: genius@starkindustries.com
- Hash: d50ba4dd3fe42e17e9faa9ec29f89708 (MD5)
- Password: iamironman
- Method: Dictionary attack
- Explanation: The password was found directly in the rockyou.txt wordlist.
- Evidence/Proof:
  > <img width="748" height="65" alt="image" src="https://github.com/user-attachments/assets/62cf5206-db59-4436-99cf-5743ad4aff5b" />
  > <img width="760" height="356" alt="image" src="https://github.com/user-attachments/assets/9fe35ef3-45a9-4479-bdc4-f8446db171b7" />


## Questions:

### 1. What is the main difference between Dictionary and Non-Dictionary attacks?

Dictionary attacks use predefined wordlists containing common passwords and phrases, making them fast and efficient but limited to known entries.  
Non-dictionary attacks (such as brute-force or rule-based attacks) generate passwords dynamically, allowing a much wider search space but requiring significantly more time and computational resources.

---

### 2. What advantage does an attacker gain by having access to the system’s database that reveals the users and the password hashes?

Access to the database allows attackers to perform **offline password cracking**. This means:

- No rate limiting
- No account lockouts
- Unlimited attempts
- No detection by the system

As a result, attackers can use powerful hardware and advanced techniques to crack passwords much more efficiently.

---

### 3. What concrete security benefits are achieved by using longer passwords instead of shorter ones?

Longer passwords significantly increase the total number of possible combinations (keyspace), making brute-force and dictionary attacks exponentially more difficult.  
This increases the time required to crack passwords and improves overall system security.

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
