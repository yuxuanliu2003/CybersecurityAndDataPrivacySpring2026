# ZAP by Checkmarx Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| 위험 수준 | Number of Alerts |
| --- | --- |
| 높음 | 0 |
| 중간 | 1 |
| 낮음 | 0 |
| Informational | 1 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| 낮음 | 경고 |  | ZAP errors logged - see the zap.log file for details | 1    |
| 낮음 | 경고 |  | ZAP warnings logged - see the zap.log file for details | 3    |
| Info | Informational | http://localhost:8003 | Percentage of responses with status code 2xx | 21 % |
| Info | Informational | http://localhost:8003 | Percentage of responses with status code 3xx | 1 % |
| Info | Informational | http://localhost:8003 | Percentage of responses with status code 4xx | 76 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with content type application/javascript | 21 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with content type text/css | 7 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with content type text/html | 28 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with content type text/plain | 28 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with method GET | 85 % |
| Info | Informational | http://localhost:8003 | Percentage of endpoints with method POST | 14 % |
| Info | Informational | http://localhost:8003 | Count of total endpoints | 14    |




## 경고

| 이름 | 위험 수준 | Number of Instances |
| --- | --- | --- |
| Absence of Anti-CSRF Tokens | 중간 | 1 |
| Authentication Request Identified | Informational | 1 |




## Alert Detail



### [ Absence of Anti-CSRF Tokens ](https://www.zaproxy.org/docs/alerts/10202/)



##### 중간 (낮음)

### 설명

No Anti-CSRF tokens were found in a HTML submission form.
A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.

CSRF attacks are effective in a number of situations, including:
    * The victim has an active session on the target site.
    * The victim is authenticated via HTTP auth on the target site.
    * The victim is on the same local network as the target site.

CSRF has primarily been used to perform an action against a target site using the victim's privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.

* URL: http://localhost:8003/register
  * Node Name: `http://localhost:8003/register`
  * Method: `GET`
  * Parameter: ``
  * 공격: ``
  * Evidence: `<form action="/register" method="POST">`
  * 기타 정보: `No known Anti-CSRF token [anticsrf, CSRFToken, __RequestVerificationToken, csrfmiddlewaretoken, authenticity_token, OWASP_CSRFTOKEN, anoncsrf, csrf_token, _csrf, _csrfSecret, __csrf_magic, CSRF, _token, _csrf_token, _csrfToken] was found in the following HTML form: [Form 1: "birthdate" "password" "username" ].`


Instances: 1

### Solution

Phase: Architecture and Design
Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
For example, use anti-CSRF packages such as the OWASP CSRFGuard.

Phase: Implementation
Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script.

Phase: Architecture and Design
Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330).
Note that this can be bypassed using XSS.

Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation.
Note that this can be bypassed using XSS.

Use the ESAPI Session Management control.
This control includes a component for CSRF.

Do not use the GET method for any request that triggers a state change.

Phase: Implementation
Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.

### Reference


* [ https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
* [ https://cwe.mitre.org/data/definitions/352.html ](https://cwe.mitre.org/data/definitions/352.html)


#### CWE Id: [ 352 ](https://cwe.mitre.org/data/definitions/352.html)


#### WASC Id: 9

#### Source ID: 3

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (높음)

### 설명

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://localhost:8003/login
  * Node Name: `http://localhost:8003/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * 공격: ``
  * Evidence: `password`
  * 기타 정보: `userParam=username
userValue=foo-bar@example.com
passwordParam=password
referer=http://localhost:8003/login
csrfToken=csrf_token`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3


