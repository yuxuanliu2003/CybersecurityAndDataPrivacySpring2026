# ZAP by Checkmarx Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## 警报汇总

| 风险水平 | 警报数量 |
| --- | --- |
| 高 | 0 |
| 中 | 0 |
| 低 | 0 |
| 信息提示 | 2 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| 信息。 | 信息提示 | http://localhost:8004 | Percentage of responses with status code 2xx | 60 % |
| 信息。 | 信息提示 | http://localhost:8004 | Percentage of responses with status code 3xx | 37 % |
| 信息。 | 信息提示 | http://localhost:8004 | Percentage of responses with status code 4xx | 1 % |
| 信息。 | 信息提示 | http://localhost:8004 | Percentage of endpoints with content type application/javascript | 25 % |
| 信息。 | 信息提示 | http://localhost:8004 | Percentage of endpoints with content type text/css | 6 % |
| 信息。 | 信息提示 | http://localhost:8004 | Percentage of endpoints with content type text/html | 31 % |
| 信息。 | 信息提示 | http://localhost:8004 | Percentage of endpoints with content type text/plain | 12 % |
| 信息。 | 信息提示 | http://localhost:8004 | Percentage of endpoints with method GET | 81 % |
| 信息。 | 信息提示 | http://localhost:8004 | Percentage of endpoints with method POST | 18 % |
| 信息。 | 信息提示 | http://localhost:8004 | Count of total endpoints | 16    |




## 警报

| 名称 | 风险水平 | 实例数 |
| --- | --- | --- |
| 会话管理响应已确定 | 信息提示 | 3 |
| 身份验证请求已确定 | 信息提示 | 1 |




## 警报详情



### [ 会话管理响应已确定 ](https://www.zaproxy.org/docs/alerts/10112/)



##### 信息提示 (中)

### 说明

给定的响应已被确定为包含会话管理令牌。 “其他信息”字段包含一组可以在基于Header的会话管理方法中使用的Header令牌。 如果请求是在具有“自动检测”的会话管理方法的上下文中，则此规则将更改会话管理以使用已确定的令牌。

* URL: http://localhost:8004/login
  * 节点名称: `http://localhost:8004/login`
  * 方法: `GET`
  * 参数: `csrf_token`
  * 攻击: ``
  * 证据: `csrf_token`
  * 其他信息: `cookie:csrf_token`
* URL: http://localhost:8004/register
  * 节点名称: `http://localhost:8004/register`
  * 方法: `GET`
  * 参数: `csrf_token`
  * 攻击: ``
  * 证据: `csrf_token`
  * 其他信息: `cookie:csrf_token`
* URL: http://localhost:8004/login
  * 节点名称: `http://localhost:8004/login`
  * 方法: `GET`
  * 参数: `csrf_token`
  * 攻击: ``
  * 证据: `csrf_token`
  * 其他信息: `cookie:csrf_token`


实例: 3

### 解决方案

这是一个信息提示警报而不是漏洞，因此没有需要修复的地方。

### 参考


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/)



#### 源 ID: 3

### [ 身份验证请求已确定 ](https://www.zaproxy.org/docs/alerts/10111/)



##### 信息提示 (高)

### 说明

给定的请求已被确定为身份验证请求。 “其他信息”字段包含一组 键=值 行，该行识别任何相关字段。 如果请求是在具有身份验证方法设置为“自动检测”的上下文中，则此规则将更改身份验证以匹配已确定的请求。

* URL: http://localhost:8004/login
  * 节点名称: `http://localhost:8004/login ()(csrf_token,password,username)`
  * 方法: `POST`
  * 参数: `username`
  * 攻击: ``
  * 证据: `password`
  * 其他信息: `userParam=username
userValue=foo-bar@example.com
passwordParam=password
referer=http://localhost:8004/login
csrfToken=csrf_token`


实例: 1

### 解决方案

这是一个信息提示警报而不是漏洞，因此没有需要修复的地方。

### 参考


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### 源 ID: 3


