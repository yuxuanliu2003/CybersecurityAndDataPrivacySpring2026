# PortSwigger
<img width="1180" height="411" alt="image" src="https://github.com/user-attachments/assets/c0159f93-b1f3-42b0-ada2-d7e986fc0aa4" />
<img width="1440" height="1255" alt="image" src="https://github.com/user-attachments/assets/8b2c8291-d33c-4801-b888-fb87490821d9" />
<img width="1440" height="1064" alt="image" src="https://github.com/user-attachments/assets/61d3a4c6-3640-49bb-93a5-cc685e19cefc" />
<img width="1463" height="1025" alt="image" src="https://github.com/user-attachments/assets/02fc5ed9-acf9-473d-bf6d-bc5a9a4c0233" />
<img width="1469" height="625" alt="image" src="https://github.com/user-attachments/assets/a9a36b66-f4ff-40eb-ac14-72cf15b09989" />

# The Booking System Project

## Phase 1
In Phase 1, I deployed the booking system using Docker and performed initial penetration testing on the registration functionality.

During the setup process, I initially attempted to install Docker using the Debian installation method, but the setup failed. After troubleshooting, I decided to switch to Docker Desktop, which provided a more stable and user-friendly environment on Windows.

What worked:
- Docker Desktop allowed successful deployment of the system
- I was able to access the application through the browser and perform testing

What didn't work:
- Debian-based Docker installation failed on my system
- Initial connection errors occurred before switching to Docker Desktop

Most time-consuming:
- Setting up the environment and resolving Docker installation issues

What I learned:
- The importance of choosing the correct Docker environment for the operating system
- How to troubleshoot container-related issues
- Basic penetration testing techniques on web applications

## Phase 2
I focused on password cracking by extracting password hashes from the system and attempting to recover the original passwords.

I used Hashcat to perform dictionary attacks with the rockyou.txt wordlist. In addition, I applied rule-based and hybrid attacks based on hints provided in the task. These methods allowed me to efficiently identify common password patterns and weak passwords.

What worked:
- Dictionary attacks using rockyou.txt were effective for several users
- Rule-based attacks helped recover passwords based on known patterns and hints
- Hashcat performed efficiently in cracking MD5 hashes

What didn't work:
- Some passwords were not directly found in the wordlist and required additional reasoning
- It was sometimes difficult to choose the correct attack method initially

Most time-consuming:
- Understanding which cracking strategy to use (dictionary vs rule-based)
- Interpreting hints and constructing possible password patterns

What I learned:
- How password hashing works and why weak algorithms like MD5 are insecure
- The difference between dictionary attacks and more advanced cracking techniques
- The importance of strong, complex passwords in preventing attacks

## Phase 3
I performed authentication testing on the booking system. I analyzed how user login, session management, and access control were implemented. The goal was to identify weaknesses in authentication and authorization mechanisms.

What worked:
- Login functionality was operational and allowed user authentication
- Sessions were created and maintained after login
- Different user roles (administrator and reserver) were visible in the system

What didn't work:
- Weak validation in authentication inputs
- Potential issues in session handling and security controls
- Lack of stronger protection mechanisms such as rate limiting or advanced validation

Most time-consuming:
- Testing different authentication scenarios and analyzing responses
- Understanding how sessions and tokens were managed in the system

What I learned:
- How authentication and session management work in practice
- The importance of secure login validation and session protection
- How attackers can exploit weak authentication mechanisms

## Phase 4
I analyzed the system from a GDPR perspective and created compliance documentation.

What worked:
- Database inspection
- Identifying personal data

What didn't work:
- Some GDPR requirements were missing in the system

Most time-consuming:
- Understanding GDPR requirements

What I learned:
- Data protection principles
- Importance of privacy policies and user rights

# Reflection
This course helped me understand both technical security and data protection principles. I learned how to identify vulnerabilities, perform penetration testing, and evaluate system security. Additionally, I gained knowledge about GDPR and the importance of protecting user data. Overall, the course improved my practical cybersecurity skills.

# Logbook
Total hours: 86 hours

Hours per topic:
- Phase 1: 15 hours
- Phase 2: 10 hours
- Phase 3: 19 hours
- Phase 4 (GDPR): 6 hours
- Cisco Networking Academy: Introduction to Cybersecurity: 15 hours
- PortSwigger: 21 hours

# Feedback

The course was very practical and helped me understand real-world cybersecurity concepts. The hands-on labs were especially useful. However, some instructions could be clearer for beginners.
