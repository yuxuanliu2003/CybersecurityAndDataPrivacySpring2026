# Authorization Test Report

> Roles tested: Guest / Reserver / Administrator  
> Testing phase: Browser testing Phase 1

## 0) Pages/Functions discovered (from UI)
<img width="1586" height="577" alt="image" src="https://github.com/user-attachments/assets/fc032b95-3a37-4374-a978-9e1a720364b1" />

---

## 1) Guest (not logged in)

### ✅ Can do
- **Can view (public) pages: http://localhost:8004/**
  > <img width="1554" height="702" alt="image" src="https://github.com/user-attachments/assets/94935a2d-dc48-4aee-9ce6-bd07f01f4b2e" />

- **Can open login page: http://localhost:8004/login**
  > <img width="755" height="438" alt="image" src="https://github.com/user-attachments/assets/943f4b28-a560-4c43-a1e4-4e18b53b6124" />

- **Can open register page: http://localhost:8004/register**
  > <img width="755" height="673" alt="image" src="https://github.com/user-attachments/assets/5985eda2-01d3-4c13-b254-0c33f5063bc9" />

---

### ❌ Cannot do
- **Cannot add a new resource (observation): The button is grayed out and cannot be clicked.**
- **Cannot add a new reservation (observation): The button is grayed out and cannot be clicked.**
  > <img width="1586" height="577" alt="image" src="https://github.com/user-attachments/assets/fc032b95-3a37-4374-a978-9e1a720364b1" />
- **When attempting to access protected endpoints (e.g., /reservation), the system returns "Unauthorized" or redirects to the homepage.**
  > <img width="780" height="366" alt="image" src="https://github.com/user-attachments/assets/ebd22f29-6812-4cf3-b584-637c168c31d9" />

### Conclusion for Guest:
#### Authentication checks are correctly implemented. The system properly blocks unauthenticated users from protected functionality.
  
---

## 2) Reserver (normal user)

### Pages visible from UI
- /resources → shows only "create resource" form (no resource list visible)
- /reservation → reservation form page
- /reservation?id=X → single reservation page (if accessible)

---

### ✅ Can do
- **Can create a new resource**  
  URL: http://localhost:8004/resources  
  > <img width="842" height="529" alt="image" src="https://github.com/user-attachments/assets/8c830efc-9bcf-4351-a3ca-59d7236d6651" />

- **Can create a new reservation**  
  URL: http://localhost:8004/reservation  
   > <img width="865" height="667" alt="image" src="https://github.com/user-attachments/assets/8325591f-e4dd-49a0-b1d4-af665ccf01ec" />

- **Can modify ownership**  
  URL example: http://localhost:8004/reservation?id=7  
  > <img width="860" height="663" alt="image" src="https://github.com/user-attachments/assets/e6addb46-b613-4f14-87fd-b1323268f724" />

- **Can edit and delete own reservation**  
  > <img width="1530" height="583" alt="image" src="https://github.com/user-attachments/assets/54320f68-6575-4077-a9af-847b75331682" />

- **Can logout**  
  URL: http://localhost:8004/logout  

---

### ❌ Cannot do
- **Cannot access reservations of other users**  
  URL example: /reservation?id=1  
  Result: **500 Internal Server Error**  
  Expected: 403 Forbidden or 404 Not Found  
  > <img width="676" height="209" alt="image" src="https://github.com/user-attachments/assets/4159630f-f2e1-4697-9ad2-bfd38a1dd6da" />

- **Cannot perform admin-level management actions (cannot delete/edit other users' reservations unless ownership is manipulated)**
  > <img width="1529" height="692" alt="image" src="https://github.com/user-attachments/assets/0d5f135d-720c-4012-b30d-c5aeb4a3cba5" />
---

### ⚠️ Potential weakness
- **Normal user can manually change the reservation "username/user" field to admin email/ID when creating a reservation.**
  - This may allow ownership confusion.
  - Server should validate that reservation owner matches the logged-in user.

### Conclusion for Reserver:
#### A reserver can manually modify the reservation owner field (e.g., enter admin email/ID), which may cause ownership confusion.  Basic ownership-based authorization exists, but error handling and ownership validation are not fully secure.

---

## 3) Administrator

### Pages visible from UI
- /resources shows only the "create resource" form (same as normal user). No extra admin UI buttons/pages found.
- /admin does not exist (Not found).
  > <img width="1531" height="702" alt="image" src="https://github.com/user-attachments/assets/efc00895-b0b5-468b-8ba0-e22d25a4e993" />


### ✅ Can do
- **Can edit and delete other users' reservations (admin privilege).**
  > <img width="1531" height="702" alt="image" src="https://github.com/user-attachments/assets/efc00895-b0b5-468b-8ba0-e22d25a4e993" />

### ❌ Cannot do / unexpected behavior
- **Trying to access other users' reservations directly by URL often results in **500 Internal Server Error** (e.g. /reservation?id=1, /reservation?id=4).**
  - Expected: 403 Forbidden or 404 Not Found
  - Actual: 500 Internal Server Error (server-side failure)
  > <img width="639" height="187" alt="image" src="https://github.com/user-attachments/assets/7d93f6e3-2685-481a-ad9c-0714707f9806" />


### ⚠️ Potential authorization weakness
- **Normal user can fill the reservation "Reserver username" field with the admin email/ID, which may confuse ownership and could lead to privilege/identity issues.**

### Conclusion for Administrator:
#### Administrative privileges exist at the functionality level (editing/deleting others’ reservations), but there is no clear separation of admin interface. Error handling for invalid reservation access is still weak.

---

## Summary

### The system implements:

- Role-based authorization (Guest / Reserver / Administrator)
- Ownership-based access control for reservations
- Authentication checks for protected endpoints

### Weaknesses:

- Unauthorized access attempts result in 500 Internal Server Error instead of proper 403/404 responses.
- Reservation ownership can be manually manipulated.
- No clearly separated admin interface.
---

# OWASP ZAP Authorization Testing – Round 2

## Target
http://localhost:8004

---

## 1. Site Discovery

ZAP discovered the following endpoints:

- /
- /login
- /register
- /reservation
- /resources
- /robots.txt
- /sitemap.xml
- /status.html
  > <img width="992" height="612" alt="image" src="https://github.com/user-attachments/assets/934335fc-e758-4c17-a9f7-9d4d1351c169" />

New pages discovered by ZAP:
- /robots.txt
- /sitemap.xml
- /status.html

No hidden admin or debug endpoints were found.

---

## 2. Role-Based Testing

### Reserver (Normal User)

Tested:
- /reservation?id=1
- /reservation?id=2
- /reservation?id=999
  > <img width="854" height="332" alt="image" src="https://github.com/user-attachments/assets/d9ff9e9d-d637-4014-ba65-7c22315186d1" />

Result:
All returned 500 Internal Server Error.

No unauthorized data exposure occurred.

---

### Administrator

Tested:
- /reservation?id=1
- /reservation?id=2
- /reservation?id=4
- /reservation?id=999
  > <img width="751" height="129" alt="image" src="https://github.com/user-attachments/assets/7a429343-cb6a-4de5-987f-7364298e98a3" />

Result:
All returned 500 Internal Server Error.

Administrator did not gain unintended access through URL manipulation.

---

## 3. Authorization Analysis

- No successful IDOR vulnerabilities detected.
- No hidden administrative endpoints discovered.
- No high or medium severity alerts detected by ZAP.

However:

Unauthorized access attempts return 500 Internal Server Error instead of proper:

- 403 Forbidden
- 404 Not Found

This indicates improper error handling for authorization failures.

---

## 4. Comparison with Manual Testing

ZAP findings were consistent with manual testing results.

ZAP did not identify additional authorization vulnerabilities beyond those discovered during manual testing.

---

## 5. Conclusion

The system enforces role-based access control and prevents direct unauthorized access.

However, authorization failure handling should be improved to return appropriate HTTP status codes instead of 500 errors.

---

# Endpoint Discovery & API Testing – Round 3
## Objectives:

1. Discover hidden or unreferenced endpoints

2. Verify if the API performs backend authorization checks

3. Test for IDORs or missing access controls
   
---

## Tools
- wfuzz 3.1.0
- Wordlist: common.txt
- Range fuzzing (1–1000)
- curl
- Browser manual testing

---

## Part 1: Directory Cracking
    wfuzz -c -w /wordlists/common.txt --hc 404 http://host.docker.internal:8004/FUZZ

### Endpoints found:

- /
- /login

- /logout

- /register

- /resources

- /reservation

### Not found:

- /admin

- /debug

- /backup

- /config

### Conclusion:

- No hidden directories or unreferenced pages found.
> <img width="1469" height="858" alt="image" src="https://github.com/user-attachments/assets/15ee75ce-4693-47fc-a8f9-6d2074268679" />

---
## Part 2: API Enumeration Testing
    wfuzz -c -z range,1-1000 --hc 404 http://host.docker.internal:8004/api/reservations/FUZZ
> <img width="1471" height="989" alt="image" src="https://github.com/user-attachments/assets/968ee7fb-02e6-4a57-a206-0c54d6d2d025" />
---
## Part 3: API Access Test Without Login
### Using curl (without logging in):
      curl -i http://host.docker.internal:8004/api/reservations/3
> <img width="1482" height="441" alt="image" src="https://github.com/user-attachments/assets/60ffc5af-9453-45d3-9566-0ddb1cd6ae37" />
### Accessed without browser login:
      http://localhost:8004/api/reservations/3
> <img width="1320" height="312" alt="image" src="https://github.com/user-attachments/assets/9b89bdf5-ac5b-4be6-be15-36af05f8d809" />
---
# 🚨 Critical Security Discovery

## Unverified users can:

### - Enumerate reservation IDs

### - Access the reservation API

### - Read complete reservation data

## This is:

### - Broken Access Control (OWASP Top 10 A01)

### - Belongs to the IDOR risk category.

## Severity: Critical⚠️
