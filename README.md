# HTTP Log Security Analysis in Splunk

Analytical HTTP security case: detection of error spikes, credential stuffing, SQLi scanning, traversal/RCE patterns, and web-shell indicators. Built with six focused SPL searches and a dashboard.

---

## Demo

- **Dashboard file:** [Dashboard_HTTP](./Dashboard_HTTP.png) — import into Splunk (Studio or SimpleXML)
- **Full report (DOCX):** [HTTP_Logs_report.docx](./HTTP_Logs_report.docx) — step-by-step searches, screenshots, observations, conclusions

---

## Data

- **Source:** `index=main`, `sourcetype=access_combined`
- **Fields:** `_time`, `clientip`, `method`, `uri`, `status`, `useragent`, `bytes`, `referer`

---

## Performed Checks and Conclusions

### 1) HTTP Status by Class (baseline 2xx/3xx/4xx/5xx)
- **Purpose:** establish baseline and spot spikes.
- **Finding:** 2xx/3xx dominate; isolated 4xx/5xx bursts align with suspect activity windows.
- **Recommendation:** alert on 5xx deviations; correlate with deploys and backend incidents.

### 2) Credential Stuffing by IP (POST `/login` 401s)
- **Purpose:** detect brute-force and password spraying.
- **Finding:** IPs exceeding threshold of failed POST `/login` in 10-minute bins.
- **Recommendation:** enable rate-limits/lockouts; enforce MFA; block repeat sources.

### 3) SQL Injection Scans
- **Purpose:** surface automation and payload probes.
- **Finding:** `sqlmap` user-agents and classic SQLi patterns from a small set of IPs.
- **Recommendation:** tighten WAF rules; throttle scanners; review affected endpoints.

### 4) 5xx Errors and Error Rate
- **Purpose:** track reliability and attack side-effects.
- **Finding:** distinct 5xx peaks; error% rises in short intervals.
- **Recommendation:** set SLOs and alerts on error%; inspect upstream health.

### 5) Traversal and RCE Patterns
- **Purpose:** catch `../`, encoded traversal, `/cgi-bin/`, `?cmd=` probes.
- **Finding:** targeted paths with 4xx/5xx responses from few sources.
- **Recommendation:** block patterns, disable legacy CGI, harden handlers.

### 6) Web-Shell Upload and Access
- **Purpose:** detect POST upload then GET execution in `/uploads/`.
- **Finding:** POST→GET to `*.php` under uploads by the same IP.
- **Recommendation:** isolate host, quarantine artifact, disable execute perms, rotate secrets.

---

## Analysis
- Baseline status mix established; anomalous windows isolated.
- Attack patterns captured: credential stuffing, SQLi, traversal/RCE.
- High-risk file ops flagged by upload→execute linkage.

## Conclusion
A repeatable HTTP threat-hunting workflow in Splunk. Six targeted searches plus a dashboard provide fast triage, clear alert thresholds, and actionable remediation paths. Full steps and screenshots are in **HTTP_Logs_report.docx**; the dashboard for import is **Dashboard_HTTP**.
