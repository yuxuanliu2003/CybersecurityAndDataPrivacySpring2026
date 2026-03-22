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
I extracted password hashes and cracked them using Hashcat.

What worked:
- Dictionary attacks using rockyou.txt
- Rule-based attacks

What didn't work:
- Some passwords required manual reasoning

Most time-consuming:
- Understanding attack methods and choosing correct strategy

What I learned:
- Password hashing and cracking techniques
- Importance of strong passwords

## Phase 3


## Phase 4
