# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 2 |
| Low | 8 |
| Informational | 4 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 1    |
| Info | Informational |  | Percentage of network failures | 8 % |
| Info | Informational | http://host.docker.internal:3000 | Percentage of responses with status code 2xx | 96 % |
| Info | Informational | http://host.docker.internal:3000 | Percentage of responses with status code 4xx | 4 % |
| Info | Informational | http://host.docker.internal:3000 | Percentage of endpoints with content type application/javascript | 77 % |
| Info | Informational | http://host.docker.internal:3000 | Percentage of endpoints with content type font/woff2 | 10 % |
| Info | Informational | http://host.docker.internal:3000 | Percentage of endpoints with content type text/css | 2 % |
| Info | Informational | http://host.docker.internal:3000 | Percentage of endpoints with content type text/html | 7 % |
| Info | Informational | http://host.docker.internal:3000 | Percentage of endpoints with method GET | 100 % |
| Info | Informational | http://host.docker.internal:3000 | Count of total endpoints | 40    |
| Info | Informational | http://host.docker.internal:3000 | Percentage of slow responses | 29 % |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Content Security Policy (CSP) Header Not Set | Medium | 4 |
| Missing Anti-clickjacking Header | Medium | 2 |
| Cross-Origin-Embedder-Policy Header Missing or Invalid | Low | 1 |
| Cross-Origin-Opener-Policy Header Missing or Invalid | Low | 1 |
| Cross-Origin-Resource-Policy Header Missing or Invalid | Low | Systemic |
| Dangerous JS Functions | Low | 2 |
| Permissions Policy Header Not Set | Low | Systemic |
| Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) | Low | 4 |
| Timestamp Disclosure - Unix | Low | 1 |
| X-Content-Type-Options Header Missing | Low | Systemic |
| Information Disclosure - Suspicious Comments | Informational | 39 |
| Modern Web Application | Informational | 4 |
| Storable and Cacheable Content | Informational | 1 |
| Storable but Non-Cacheable Content | Informational | Systemic |




## Alert Detail



### [ Content Security Policy (CSP) Header Not Set ](https://www.zaproxy.org/docs/alerts/10038/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://host.docker.internal:3000
  * Node Name: `http://host.docker.internal:3000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/
  * Node Name: `http://host.docker.internal:3000/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/robots.txt
  * Node Name: `http://host.docker.internal:3000/robots.txt`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/sitemap.xml
  * Node Name: `http://host.docker.internal:3000/sitemap.xml`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``


Instances: 4

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
* [ https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html ](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://w3c.github.io/webappsec-csp/ ](https://w3c.github.io/webappsec-csp/)
* [ https://web.dev/articles/csp ](https://web.dev/articles/csp)
* [ https://caniuse.com/#feat=contentsecuritypolicy ](https://caniuse.com/#feat=contentsecuritypolicy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Missing Anti-clickjacking Header ](https://www.zaproxy.org/docs/alerts/10020/)



##### Medium (Medium)

### Description

The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.

* URL: http://host.docker.internal:3000
  * Node Name: `http://host.docker.internal:3000`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/
  * Node Name: `http://host.docker.internal:3000/`
  * Method: `GET`
  * Parameter: `x-frame-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``


Instances: 2

### Solution

Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app.
If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's "frame-ancestors" directive.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options)


#### CWE Id: [ 1021 ](https://cwe.mitre.org/data/definitions/1021.html)


#### WASC Id: 15

#### Source ID: 3

### [ Cross-Origin-Embedder-Policy Header Missing or Invalid ](https://www.zaproxy.org/docs/alerts/90004/)



##### Low (Medium)

### Description

Cross-Origin-Embedder-Policy header is a response header that prevents a document from loading any cross-origin resources that don't explicitly grant the document permission (using CORP or CORS).

* URL: http://host.docker.internal:3000
  * Node Name: `http://host.docker.internal:3000`
  * Method: `GET`
  * Parameter: `Cross-Origin-Embedder-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``


Instances: 1

### Solution

Ensure that the application/web server sets the Cross-Origin-Embedder-Policy header appropriately, and that it sets the Cross-Origin-Embedder-Policy header to 'require-corp' for documents.
If possible, ensure that the end user uses a standards-compliant and modern web browser that supports the Cross-Origin-Embedder-Policy header (https://caniuse.com/mdn-http_headers_cross-origin-embedder-policy).

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Embedder-Policy)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 14

#### Source ID: 3

### [ Cross-Origin-Opener-Policy Header Missing or Invalid ](https://www.zaproxy.org/docs/alerts/90004/)



##### Low (Medium)

### Description

Cross-Origin-Opener-Policy header is a response header that allows a site to control if others included documents share the same browsing context. Sharing the same browsing context with untrusted documents might lead to data leak.

* URL: http://host.docker.internal:3000
  * Node Name: `http://host.docker.internal:3000`
  * Method: `GET`
  * Parameter: `Cross-Origin-Opener-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``


Instances: 1

### Solution

Ensure that the application/web server sets the Cross-Origin-Opener-Policy header appropriately, and that it sets the Cross-Origin-Opener-Policy header to 'same-origin' for documents.
'same-origin-allow-popups' is considered as less secured and should be avoided.
If possible, ensure that the end user uses a standards-compliant and modern web browser that supports the Cross-Origin-Opener-Policy header (https://caniuse.com/mdn-http_headers_cross-origin-opener-policy).

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Cross-Origin-Opener-Policy)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 14

#### Source ID: 3

### [ Cross-Origin-Resource-Policy Header Missing or Invalid ](https://www.zaproxy.org/docs/alerts/90004/)



##### Low (Medium)

### Description

Cross-Origin-Resource-Policy header is an opt-in header designed to counter side-channels attacks like Spectre. Resource should be specifically set as shareable amongst different origins.

* URL: http://host.docker.internal:3000/_next/static/chunks/%255Broot-of-the-server%255D__09hpsjx._.css
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/[root-of-the-server]__09hpsjx._.css`
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/chunks/%255Bturbopack%255D_browser_dev_hmr-client_hmr-client_ts_1xx01vv._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/[turbopack]_browser_dev_hmr-client_hmr-client_ts_1xx01vv._.js`
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/media/03fc1b4a8d284b5e-s.p.0wiir8udbzjvx.woff2
  * Node Name: `http://host.docker.internal:3000/_next/static/media/03fc1b4a8d284b5e-s.p.0wiir8udbzjvx.woff2`
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/media/23b7a97ae3b5c134-s.p.226pwps5o-gq_.woff2
  * Node Name: `http://host.docker.internal:3000/_next/static/media/23b7a97ae3b5c134-s.p.226pwps5o-gq_.woff2`
  * Method: `GET`
  * Parameter: `Cross-Origin-Resource-Policy`
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/media/99e609270109b47d-s.p.40sczeszzbjw1.woff2
  * Node Name: `http://host.docker.internal:3000/_next/static/media/99e609270109b47d-s.p.40sczeszzbjw1.woff2`
  * Method: `GET`
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

### [ Dangerous JS Functions ](https://www.zaproxy.org/docs/alerts/10110/)



##### Low (Low)

### Description

A dangerous JS function seems to be in use that would leave the site vulnerable.

* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_react-server-dom-turbopack_164kp-6._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_react-server-dom-turbopack_164kp-6._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `eval(`
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `eval(`
  * Other Info: ``


Instances: 2

### Solution

See the references for security advice on the use of these functions.

### Reference


* [ https://v17.angular.io/guide/security ](https://v17.angular.io/guide/security)


#### CWE Id: [ 749 ](https://cwe.mitre.org/data/definitions/749.html)


#### Source ID: 3

### [ Permissions Policy Header Not Set ](https://www.zaproxy.org/docs/alerts/10063/)



##### Low (Medium)

### Description

Permissions Policy Header is an added layer of security that helps to restrict from unauthorized access or usage of browser/client features by web resources. This policy ensures the user privacy by limiting or specifying the features of the browsers can be used by the web resources. Permissions Policy provides a set of standard HTTP headers that allow website owners to limit which features of browsers can be used by the page such as camera, microphone, location, full screen etc.

* URL: http://host.docker.internal:3000
  * Node Name: `http://host.docker.internal:3000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/chunks/%255Bturbopack%255D_browser_dev_hmr-client_hmr-client_ts_1xx01vv._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/[turbopack]_browser_dev_hmr-client_hmr-client_ts_1xx01vv._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/chunks/_1anvha4._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/_1anvha4._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_1amofcm._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_1amofcm._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/chunks/src_lib_api_ts_1avs92-._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/src_lib_api_ts_1avs92-._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution

Ensure that your web server, application server, load balancer, etc. is configured to set the Permissions-Policy header.

### Reference


* [ https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy ](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy)
* [ https://developer.chrome.com/blog/feature-policy/ ](https://developer.chrome.com/blog/feature-policy/)
* [ https://scotthelme.co.uk/a-new-security-header-feature-policy/ ](https://scotthelme.co.uk/a-new-security-header-feature-policy/)
* [ https://w3c.github.io/webappsec-feature-policy/ ](https://w3c.github.io/webappsec-feature-policy/)
* [ https://www.smashingmagazine.com/2018/12/feature-policy/ ](https://www.smashingmagazine.com/2018/12/feature-policy/)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) ](https://www.zaproxy.org/docs/alerts/10037/)



##### Low (Medium)

### Description

The web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.

* URL: http://host.docker.internal:3000
  * Node Name: `http://host.docker.internal:3000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Next.js`
  * Other Info: ``
* URL: http://host.docker.internal:3000/
  * Node Name: `http://host.docker.internal:3000/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Next.js`
  * Other Info: ``
* URL: http://host.docker.internal:3000/robots.txt
  * Node Name: `http://host.docker.internal:3000/robots.txt`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Next.js`
  * Other Info: ``
* URL: http://host.docker.internal:3000/sitemap.xml
  * Node Name: `http://host.docker.internal:3000/sitemap.xml`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `X-Powered-By: Next.js`
  * Other Info: ``


Instances: 4

### Solution

Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.

### Reference


* [ https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework ](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework)
* [ https://www.troyhunt.com/shhh-dont-let-your-response-headers/ ](https://www.troyhunt.com/shhh-dont-let-your-response-headers/)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server. - Unix

* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_react-dom_096_9a-._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_react-dom_096_9a-._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `2080374784`
  * Other Info: `2080374784, which evaluates to: 2035-12-04 09:53:04.`


Instances: 1

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ https://cwe.mitre.org/data/definitions/200.html ](https://cwe.mitre.org/data/definitions/200.html)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ X-Content-Type-Options Header Missing ](https://www.zaproxy.org/docs/alerts/10021/)



##### Low (Medium)

### Description

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.

* URL: http://host.docker.internal:3000/_next/static/chunks/%255Bturbopack%255D_browser_dev_hmr-client_hmr-client_ts_1xx01vv._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/[turbopack]_browser_dev_hmr-client_hmr-client_ts_1xx01vv._.js`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:3000/_next/static/media/03fc1b4a8d284b5e-s.p.0wiir8udbzjvx.woff2
  * Node Name: `http://host.docker.internal:3000/_next/static/media/03fc1b4a8d284b5e-s.p.0wiir8udbzjvx.woff2`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:3000/_next/static/media/23b7a97ae3b5c134-s.p.226pwps5o-gq_.woff2
  * Node Name: `http://host.docker.internal:3000/_next/static/media/23b7a97ae3b5c134-s.p.226pwps5o-gq_.woff2`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:3000/_next/static/media/99e609270109b47d-s.p.40sczeszzbjw1.woff2
  * Node Name: `http://host.docker.internal:3000/_next/static/media/99e609270109b47d-s.p.40sczeszzbjw1.woff2`
  * Method: `GET`
  * Parameter: `x-content-type-options`
  * Attack: ``
  * Evidence: ``
  * Other Info: `This issue still applies to error type pages (401, 403, 500, etc.) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.
At "High" threshold this scan rule will not alert on client or server error responses.`
* URL: http://host.docker.internal:3000/_next/static/media/effe91970fc4db64-s.p.0oace-s_gkfks.woff2
  * Node Name: `http://host.docker.internal:3000/_next/static/media/effe91970fc4db64-s.p.0oace-s_gkfks.woff2`
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

### [ Information Disclosure - Suspicious Comments ](https://www.zaproxy.org/docs/alerts/10027/)



##### Informational (Medium)

### Description

The response appears to contain suspicious comments which may help an attacker.

* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` * By default React Query will use the batch `
  * Other Info: `The following pattern was used: \bQUERY\b and was detected 6 times, the first in likely comment: "/**
     * Use this method to set a custom function to batch notifications together into a single tick.
     * By default React ", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` is skipped, try to select the next sibling an`
  * Other Info: `The following pattern was used: \bSELECT\b and was detected 2 times, the first in likely comment: "// If the element is skipped, try to select the next sibling and try again.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// TODO: Once we start trac`
  * Other Info: `The following pattern was used: \bTODO\b and was detected 19 times, the first in likely comment: "// TODO: Once we start tracking back/forward history at each route level,", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `appens often if the user doesn't pass a ref `
  * Other Info: `The following pattern was used: \bUSER\b and was detected 9 times, the first in likely comment: "// (this happens often if the user doesn't pass a ref to Link/Form/Image)", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `is already caused a bug where the first chi`
  * Other Info: `The following pattern was used: \bBUG\b and was detected 2 times, the first in likely comment: "// This already caused a bug where the first child was a <link/> in head.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `lbacks or functions where reading the latest `
  * Other Info: `The following pattern was used: \bWHERE\b and was detected 3 times, the first in likely comment: "/**
   * Imperative (non-reactive) way to retrieve data for a QueryKey.
   * Should only be used in callbacks or functions where", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_1c-nb-8._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `t function modified from nodejs`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 18 times, the first in likely comment: "// Format function modified from nodejs", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_es-toolkit_dist_12huve3._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_es-toolkit_dist_12huve3._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `an array of numbers from `start` (inclusive)`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 9 times, the first in likely comment: "/**
* Returns an array of numbers from `start` (inclusive) to `end` (exclusive), incrementing by `step`.
*
* @param start - The ", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_es-toolkit_dist_12huve3._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_es-toolkit_dist_12huve3._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ect - The object to query.
* @param path - Th`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected 4 times, the first in likely comment: "/**
* Retrieves the value at a given path from an object. If the resolved value is undefined, the defaultValue is returned inste", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_es-toolkit_dist_12huve3._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_es-toolkit_dist_12huve3._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `rray of objects by 'user' in ascending order`
  * Other Info: `The following pattern was used: \bUSER\b and was detected in likely comment: "/**
* Sorts an array of objects based on multiple properties and their corresponding order directions.
*
* This function takes a", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` find the pathname, query and hash and return`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected in likely comment: "/**
 * Given a path this function will find the pathname, query and hash and return
 * them. This is useful to parse full paths ", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` with null captured later.`
  * Other Info: `The following pattern was used: \bLATER\b and was detected in likely comment: "// (e.g., in onRecoverableError) with null captured later.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// TODO: We should hoist th`
  * Other Info: `The following pattern was used: \bTODO\b and was detected 16 times, the first in likely comment: "// TODO: We should hoist the search params out of the FlightRouterState", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// from user code generated by W`
  * Other Info: `The following pattern was used: \bUSER\b and was detected 7 times, the first in likely comment: "// from user code generated by Webpack. For more information see", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// where rust does not have `
  * Other Info: `The following pattern was used: \bWHERE\b and was detected 7 times, the first in likely comment: "// where rust does not have easy way to repreesnt js's 53-bit float number type for the matching", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ntime expose Object from vm, being that kind`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 32 times, the first in likely comment: "/**
   * this used to be previously:
   *
   * `return prototype === null || prototype === Object.prototype`
   *
   * but Edge ", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_1ybzpk2._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `to report this as a bug in Next.js.`
  * Other Info: `The following pattern was used: \bBUG\b and was detected 2 times, the first in likely comment: "// user to report this as a bug in Next.js.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_1amofcm._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_1amofcm._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// TODO: rename these field`
  * Other Info: `The following pattern was used: \bTODO\b and was detected 3 times, the first in likely comment: "// TODO: rename these fields to something more meaningful.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_1amofcm._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_next_dist_compiled_1amofcm._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ogic is copy-pasted from similar logic in th`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 4 times, the first in likely comment: "// This logic is copy-pasted from similar logic in the DevTools backend.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_component_0t5m2pp._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_component_0t5m2pp._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// Magic number from d3`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 3 times, the first in likely comment: "// Magic number from d3", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_component_0t5m2pp._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_component_0t5m2pp._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// TODO: Generic Polar Hook`
  * Other Info: `The following pattern was used: \bTODO\b and was detected in likely comment: "// TODO: Generic Polar Hook", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_component_0t5m2pp._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_component_0t5m2pp._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// where to trim.  This shou`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected in likely comment: "// where to trim.  This should not happen :tm:", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_component_0t5m2pp._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_component_0t5m2pp._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `bers;
     * if the user provides a zero or `
  * Other Info: `The following pattern was used: \bUSER\b and was detected 3 times, the first in likely comment: "/*
     * If it just so happens that the combination of width, height, and aspect ratio
     * results in fixed dimensions, then", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_util_196ddir._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_util_196ddir._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` and compute domain from data later */`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 7 times, the first in likely comment: "/* ignore the exception and compute domain from data later */", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_util_196ddir._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_util_196ddir._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// The ticks set by user should only affect `
  * Other Info: `The following pattern was used: \bUSER\b and was detected 7 times, the first in likely comment: "// The ticks set by user should only affect the ticks adjacent to axis line", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_util_196ddir._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_util_196ddir._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `h to find the index where x would fit in arra`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected 2 times, the first in likely comment: "/**
 * Binary search to find the index where x would fit in array a.
 * Works for arrays that are sorted both ascending and desc", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_util_196ddir._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/node_modules_recharts_es6_util_196ddir._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `t* value assertions later.
   */`
  * Other Info: `The following pattern was used: \bLATER\b and was detected in likely comment: "/*
   * Since the function guarantees `D extends Partial<T>`, this assignment is safe.
   * It allows TypeScript to work with th", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// Fetch user profile from /api/a`
  * Other Info: `The following pattern was used: \bUSER\b and was detected 15 times, the first in likely comment: "// Fetch user profile from /api/auth/me", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `d so we can migrate later. Cross-component sy`
  * Other Info: `The following pattern was used: \bLATER\b and was detected in likely comment: "// other. Versioned so we can migrate later. Cross-component sync via a", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `o a toast triggered from inside a dialog (e.`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 7 times, the first in likely comment: "// z-50) so a toast triggered from inside a dialog (e.g. "Copied CVE id"", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ort signal so React Query cleanup still works`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected 7 times, the first in likely comment: "// Forward caller's abort signal so React Query cleanup still works", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/src_0siywz6._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `rovides a synthetic admin context so the app
`
  * Other Info: `The following pattern was used: \bADMIN\b and was detected 5 times, the first in likely comment: "/**
 * Authentication context and provider for HCL IAM OIDC integration.
 *
 * Wraps the React tree with auth state: user identi", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ` a Refresh Boundary later.`
  * Other Info: `The following pattern was used: \bLATER\b and was detected in likely comment: "// still a Refresh Boundary later.", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `/ same URL: https://bugs.webkit.org/show_bug`
  * Other Info: `The following pattern was used: \bBUGS\b and was detected in likely comment: "// same URL: https://bugs.webkit.org/show_bug.cgi?id=187726", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `// TODO(alexkirsz) Do we ne`
  * Other Info: `The following pattern was used: \bTODO\b and was detected 5 times, the first in likely comment: "// TODO(alexkirsz) Do we need this check?", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ative to the origin where a chunk can be fetc`
  * Other Info: `The following pattern was used: \bWHERE\b and was detected 4 times, the first in likely comment: "/**
 * Returns the URL relative to the origin where a chunk can be fetched from.
 */", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `ead of accessing it from the module object t`
  * Other Info: `The following pattern was used: \bFROM\b and was detected 25 times, the first in likely comment: "// We need to store this here instead of accessing it from the module object to:", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `emove fragments and query parameters since th`
  * Other Info: `The following pattern was used: \bQUERY\b and was detected 6 times, the first in likely comment: "/**
 * Remove fragments and query parameters since they are never part of the context map keys
 *
 * This matches how we parse p", see evidence field for the suspicious comment/snippet.`
* URL: http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/turbopack-_01_ro95._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `es the HMR API that user code calls (module.`
  * Other Info: `The following pattern was used: \bUSER\b and was detected 2 times, the first in likely comment: "/**
 * Creates the module.hot API object and its internal state.
 * This provides the HMR API that user code calls (module.hot.a", see evidence field for the suspicious comment/snippet.`


Instances: 39

### Solution

Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.

### Reference



#### CWE Id: [ 615 ](https://cwe.mitre.org/data/definitions/615.html)


#### WASC Id: 13

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

* URL: http://host.docker.internal:3000
  * Node Name: `http://host.docker.internal:3000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="/_next/static/chunks/node_modules_next_dist_compiled_next-devtools_index_090k2jm.js" async=""></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://host.docker.internal:3000/
  * Node Name: `http://host.docker.internal:3000/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="/_next/static/chunks/node_modules_next_dist_compiled_next-devtools_index_090k2jm.js" async=""></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://host.docker.internal:3000/robots.txt
  * Node Name: `http://host.docker.internal:3000/robots.txt`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="/_next/static/chunks/node_modules_next_dist_compiled_next-devtools_index_090k2jm.js" async=""></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`
* URL: http://host.docker.internal:3000/sitemap.xml
  * Node Name: `http://host.docker.internal:3000/sitemap.xml`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="/_next/static/chunks/node_modules_next_dist_compiled_next-devtools_index_090k2jm.js" async=""></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`


Instances: 4

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3

### [ Storable and Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, and may be retrieved directly from the cache, rather than from the origin server by the caching servers, in response to similar requests from other users. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where "shared" caching servers such as "proxy" caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.

* URL: http://host.docker.internal:3000/_next/static/media/99e609270109b47d-s.p.40sczeszzbjw1.woff2
  * Node Name: `http://host.docker.internal:3000/_next/static/media/99e609270109b47d-s.p.40sczeszzbjw1.woff2`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `max-age=31536000`
  * Other Info: ``


Instances: 1

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

### [ Storable but Non-Cacheable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are storable by caching components such as proxy servers, but will not be retrieved directly from the cache, without validating the request upstream, in response to similar requests from other users.

* URL: http://host.docker.internal:3000
  * Node Name: `http://host.docker.internal:3000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/chunks/_1anvha4._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/_1anvha4._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``
* URL: http://host.docker.internal:3000/_next/static/chunks/src_lib_api_ts_1avs92-._.js
  * Node Name: `http://host.docker.internal:3000/_next/static/chunks/src_lib_api_ts_1avs92-._.js`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-cache`
  * Other Info: ``

Instances: Systemic


### Solution



### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3


