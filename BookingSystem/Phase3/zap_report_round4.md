# ZAP by Checkmarx Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| 위험 수준 | Number of Alerts |
| --- | --- |
| 높음 | 0 |
| 중간 | 0 |
| 낮음 | 0 |
| Informational | 2 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| 낮음 | 경고 |  | ZAP warnings logged - see the zap.log file for details | 1    |
| Info | Informational | http://localhost:8004 | Percentage of responses with status code 2xx | 23 % |
| Info | Informational | http://localhost:8004 | Percentage of responses with status code 3xx | 3 % |
| Info | Informational | http://localhost:8004 | Percentage of responses with status code 4xx | 73 % |
| Info | Informational | http://localhost:8004 | Percentage of endpoints with content type application/javascript | 25 % |
| Info | Informational | http://localhost:8004 | Percentage of endpoints with content type text/css | 6 % |
| Info | Informational | http://localhost:8004 | Percentage of endpoints with content type text/html | 31 % |
| Info | Informational | http://localhost:8004 | Percentage of endpoints with content type text/plain | 12 % |
| Info | Informational | http://localhost:8004 | Percentage of endpoints with method GET | 81 % |
| Info | Informational | http://localhost:8004 | Percentage of endpoints with method POST | 18 % |
| Info | Informational | http://localhost:8004 | Count of total endpoints | 16    |




## 경고

| 이름 | 위험 수준 | Number of Instances |
| --- | --- | --- |
| Authentication Request Identified | Informational | 1 |
| Session Management Response Identified | Informational | 3 |




## Alert Detail



### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (높음)

### 설명

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://localhost:8004/login
  * Node Name: `http://localhost:8004/login ()(csrf_token,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * 공격: ``
  * Evidence: `password`
  * 기타 정보: `userParam=username
userValue=foo-bar@example.com
passwordParam=password
referer=http://localhost:8004/login
csrfToken=csrf_token`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (중간)

### 설명

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: http://localhost:8004/login
  * Node Name: `http://localhost:8004/login`
  * Method: `GET`
  * Parameter: `csrf_token`
  * 공격: ``
  * Evidence: `csrf_token`
  * 기타 정보: `cookie:csrf_token`
* URL: http://localhost:8004/register
  * Node Name: `http://localhost:8004/register`
  * Method: `GET`
  * Parameter: `csrf_token`
  * 공격: ``
  * Evidence: `csrf_token`
  * 기타 정보: `cookie:csrf_token`
* URL: http://localhost:8004/register
  * Node Name: `http://localhost:8004/register`
  * Method: `GET`
  * Parameter: `csrf_token`
  * 공격: ``
  * Evidence: `csrf_token`
  * 기타 정보: `cookie:csrf_token`


Instances: 3

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/)



#### Source ID: 3



