# Authorization testing performed for Phase 3 (26.02-01.03.2026)
## Environment:

- Docker-based booking system running on http://localhost:8004/.

## Activity:

- Deployed and tested the current version of the booking system.
- Performed manual authorization testing for three roles: Guest, Reserver, and Administrator.
- Tested direct URL access to protected endpoints.
- Compared expected vs actual authorization behavior.
- Documented findings in auth_test_report.md.

## Tools Used:

- Browser manual testing
- Docker
- Operating System: Linux (Docker container environment)

## What I did:

- Deployed the application inside Docker.
- Logged in as Guest (not logged in), Reserver, and Administrator.
- Identified accessible pages via UI navigation.
- Manually modified URLs to test authorization enforcement (e.g., /reservation?id=X).
- Tested logout behavior and attempted access to protected resources.
- Tested whether normal users could access or modify other users’ reservations.
- Tested whether administrators had elevated privileges.
- Documented all findings with URLs and observed responses.

## Findings:

- Guest users were correctly blocked from protected functionality and redirected or shown “Unauthorized”.

- Reserver users could:

- Create resources

- Create reservations

- Edit and delete their own reservations

- Reserver users could not access other users’ reservations, but attempting direct URL manipulation resulted in:

  - 500 Internal Server Error

- Expected behavior:
  - 403 Forbidden or 404 Not Found

  > This indicates improper error handling for unauthorized access.

- Administrator users could:

  - Edit and delete other users’ reservations

## However:

- No separate admin dashboard or admin-specific UI was found.

- Some invalid reservation ID access also returned 500 errors.

- Potential authorization weaknesses identified:

- Unauthorized access attempts trigger 500 errors instead of proper authorization responses.

- Reservation ownership can potentially be manipulated via manual input of user/email field.

- Server-side validation of ownership should be stricter.

## Problems encountered:

- Internal Server Error responses instead of proper 403/404 responses made it harder to distinguish between authorization failure and server-side bug.


## What I learned:

- How role-based authorization works in practice.

- The difference between authentication and authorization.

- Why UI restrictions are not sufficient for security.

- How direct URL manipulation can reveal authorization weaknesses.

- Why proper HTTP status codes (403 vs 500) are important in secure application design.

#### This testing process demonstrated that even when basic authorization logic exists, improper error handling and insufficient server-side validation can introduce security risks.

#### Time Spent:

#### - 8 hours

---

# ZAP Authorization Testing for Phase 3
## Environment:

Docker-based Booking System running on localhost:8004
OWASP ZAP 2.17.0 (Chinese interface)

## Activity:

Performed authorization testing using OWASP ZAP.
Executed automated scan and forced browsing.
Tested application behavior under different roles (Reserver and Administrator).
Compared ZAP findings with manual authorization testing results.

## Tools Used:

OWASP ZAP
Browser manual testing
Docker
Operating System: Windows (Docker environment)

## What I did:

Launched OWASP ZAP and scanned the application at http://localhost:8004
.

Reviewed discovered endpoints in the Site Tree.

Identified additional endpoints:

/robots.txt

/sitemap.xml

/status.html

Performed forced browsing to detect hidden directories.

Logged in as normal user and manually accessed:

/reservation?id=1

/reservation?id=2

/reservation?id=999

Observed HTTP responses in ZAP History tab.

Repeated the same tests while logged in as Administrator.

Compared response codes and behavior between roles.

## Findings:

No hidden admin panels or debug endpoints were discovered.

No High or Medium severity alerts were reported by ZAP.

All unauthorized reservation ID access attempts returned:

500 Internal Server Error

This occurred for both normal user and administrator accounts.

No successful IDOR vulnerability was identified.

However, returning 500 instead of 403 or 404 indicates improper authorization error handling.

## Comparison with Manual Testing:

ZAP results were consistent with manual testing findings.

No additional authorization bypass vulnerabilities were discovered.

## What I learned:

How to use OWASP ZAP to analyze site structure and request history.

How to verify authorization behavior using HTTP status codes.

How to test ID-based access control using direct URL manipulation.

The importance of returning proper HTTP status codes (403/404) instead of 500 errors for unauthorized access attempts.

### Time Spent:

### 6 hours
