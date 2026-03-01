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
