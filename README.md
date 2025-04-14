# Splunk Monitoring Environment 
##### UCI's Cybersecurity Boot Camp Project # 3: Building a Splunk Monitoring Environment
Access to project deliverable: <a href="https://docs.google.com/presentation/d/126MWW7FZ0Y4QnIX8CaVO_7Fv5AIZq86ygWENP0Joo8Y/edit?usp=sharing"> Splunk Monitoring Presentation

## Objective Summary
This project focused on building a custom security monitoring environment using Splunk to detect, analyze, and respond to potential cyber threats. It involved configuring log sources, analyzing security events, and refining alerting thresholds to enhance detection accuracy. Simulated attacks were conducted to validate threat detection capabilities, ensuring a proactive approach to cybersecurity monitoring and incident response.

## Project Highlights
- Configured Splunk for centralized log collection and security event monitoring.
- Analyzed Windows Server logs to detect suspicious login attempts, failed authentication events, and account modifications.
- Analyzed Apache web server logs to identify anomalies, including spikes in HTTP POST activity and unusual referrer domains.
- Used Splunk to develop custom alerts to detect unauthorized access attempts, international logins, and brute force attacks.
- Created dashboards to analyze security data, aiding in faster threat detection, response, and data-driven decisions.
- Presented the findings and security recommendations.

## Technical Skills Learned
- **Log Analysis**: Interpreting and analyzing logs from Windows Server and Apache web servers.
- **SIEM Management**: Configuring Splunk to collect, process, and visualize security event data.
- **Threat Detection**: Identifying suspicious activity, including brute force attacks, unauthorized logins, and reconnaissance attempts.
- **Alert Tuning**: Refining alert thresholds to minimize false positives while maintaining security.
- **Network Security**: Understanding common attack vectors and defensive strategies to secure enterprise environments.
- **Incident Response Planning**: Creating a structured plan to improve detection and response efficiency.

## Tools & Environments Used
- **SIEM**: Splunk
- **Log Analysis**: Splunk SPL
- **Windows Server**: Event log analysis
- **Apache Web Server**: HTTP request log analysis
- **Geolocation Tools**: IP mapping and geostats
- **Virtual Environments**: Ubuntu Linux

## Scenario Overview
Security monitoring environment set up for fictional organization "VSI" included log analysis, threshold tuning, detection alert creation, forensic analysis, and presentation of findings using simulated attack data.

## Summary of Project Steps
1. **Splunk Configuration**: Log ingestion from Windows Server and Apache web server.
2. **Log Data Analysis**: Normal vs. suspicious activity trends.
3. **Alert Development**: Created alerts for abnormal behaviors.
4. **Threat Simulation**: Uploaded simulated attack logs.
5. **Dashboard Creation**: Visualized trends using time-series and geolocation data.
6. **Threshold Tuning**: Minimized false positives.

## Detailed Project Steps
### 1. Splunk Configuration
- Installed on VM.
- Ingested Windows & Apache logs.
- Set up parsing/indexing rules.

### 2. Log Data Analysis
Used SPL to:
- Identify unique activity signatures:
  ```spl
  source="windows_server_logs.csv" | dedup signature, signature_id | table signature, signature_id
  ```
  <img width="682" alt="image" src="https://github.com/user-attachments/assets/01cc54ba-6e74-4103-a938-717cd36763f8" />

- Display severity levels:
  ```spl
  source="windows_server_logs.csv" | stats count by severity | eventstats sum(count) as total_count | eval percentage=(count/total_count)*100 | table severity, count, percentage
  ```
  <img width="1787" alt="image" src="https://github.com/user-attachments/assets/a4f440aa-3a5d-4ffa-b39c-24f3357f8841" />

- Analyze success/failure:
  ```spl
  source="windows_server_logs.csv" | stats count by status | eventstats sum(count) as total_count | eval percentage=(count/total_count)*100 | table status, count, percentage
  ```
  <img width="1690" alt="image" src="https://github.com/user-attachments/assets/66f8d91e-780a-4f6f-836e-57b610dcbe6a" />

- HTTP method breakdown:
  ```spl
  source="apache_logs.txt" method="*" | stats count by method | eventstats sum(count) as total_count | eval percentage=(count/total_count)*100 | table method, count, percentage | sort -count
  ```
  <img width="1694" alt="image" src="https://github.com/user-attachments/assets/e6a61b25-af45-4716-8ad5-b498cfa116b5" />

- Apache HTTP status analysis:
  ```spl
  source="apache_logs.txt" status="*" | stats count by status | sort -count
  ```
  <img width="1694" alt="image" src="https://github.com/user-attachments/assets/dd0fd8d7-e124-404e-9bfd-b4fe1468428f" />

### 3. Alert Development
- Brute force detection:
  ```spl
  source="windows_server_logs.csv" status="failure" | timechart span=1h count as Failed_Activity
  ```
  <img width="722" alt="image" src="https://github.com/user-attachments/assets/4756af44-781f-4bf3-b813-8d5237ad0b13" />

- Average/stdev analysis:
  ```spl
  source="windows_server_logs.csv" status="failure" | bin _time span=1h | stats count as failures by _time | stats avg(failures) as avg_failures, stdev(failures) as stdev_failures
  ```
  <img width="728" alt="image" src="https://github.com/user-attachments/assets/131e71bc-5ae9-4655-ba43-9298cfac20ec" />

- Hourly success tracking:
  ```spl
  source="windows_server_logs.csv" signature_id=4624
  ```
  <img width="639" alt="image" src="https://github.com/user-attachments/assets/1dc193b2-1f96-419f-abba-87d6c9722207" />

- Non-US login attempts:
  ```spl
  source="apache_logs.txt" | iplocation clientip | where Country!="United States"
  ```
  <img width="1653" alt="image" src="https://github.com/user-attachments/assets/3e037ab7-c5cd-4d21-81e2-9ee63e2fe173" />

- POST request alerts:
  ```spl
  source="apache_logs.txt" method=POST
  ```
  <img width="1674" alt="image" src="https://github.com/user-attachments/assets/ab80c19d-9bb9-41e6-bffb-6f1ba3b76c00" />

### 4. Analyze Attack Logs
- Uploaded & analyzed spikes in:
  - Failed/successful logins
  - POST requests
  - Access from foreign IPs

### 5. Dashboard Creation
- Login trends:
  ```spl
  source="windows_server_logs.csv" user="*" | timechart count by user
  ```
  <img width="642" alt="image" src="https://github.com/user-attachments/assets/ff38deed-1d76-48ef-b260-a401a58d5c28" />

- Signature counts:
  ```spl
  source="windows_server_attack_logs.csv" signature="*" | stats count by signature
  ```
  <img width="646" alt="image" src="https://github.com/user-attachments/assets/a23635d6-e5db-4555-bc66-daa36319029d" />

- HTTP method timechart:
  ```spl
  source="apache_logs.txt" method="*" | timechart span=1hr count as HTTP_Methods
  ```
  <img width="1679" alt="image" src="https://github.com/user-attachments/assets/c2a74366-9782-43d0-92be-f993ff21721b" />


### 6. Threshold Tuning
- Business-hour based alerts
- Reduced alert fatigue

## Evidence Summary
### Timeframes
- **Windows Logs**: Suspicious 1–2:40 AM & 9–10:50 AM
- **Apache Logs**: Spikes at 6 PM, 8 PM, 8:05–8:06 PM

### Users
- **User_a**: Activity 1:50–2:40 AM
- **User_k**: Activity 9:10–10:50 AM

### IPs
- Foreign IPs (e.g., Kiev): 454 events

### Attack Evidence
- Successful logins at odd hours
- 1,323 hits on `account_logon.php`
- HTTP POST spike from 106 to 1,324
- High 404 error rate
- 937 events from foreign IPs between 8–9 PM

## Conclusion
This project provided hands-on experience configuring Splunk, analyzing logs, developing alerts, and interpreting attack patterns. It reinforced key cybersecurity skills necessary for real-world SIEM and SOC work.

## Resources
- [Splunk Documentation](https://docs.splunk.com)
- edX Cybersecurity Bootcamp
- [CISA Incident Response Plan](https://www.cisa.gov/sites/default/files/publications/Incident-Response-Plan-Basics_508c.pdf)
