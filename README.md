# SQLi SCANNER
**A Simple SQL Injection Scanner for Authorized Lab Testing**

SQLi SCANNER is a PHP-based web application security testing tool designed to identify possible SQL Injection indicators in URL query parameters.

It performs three detection techniques:
- Error-based Detection
- Boolean-based Detection
- Time-based Detection

The scanner displays scan findings, risk assessment, scan history and CSV reports.

> **Disclaimer:** This tool is developed for educational purposes and authorized security testing only. Only scan systems that you own or have explicit permission to test.

---

## 1. Project Information

| Item | Details |
|---|---|
| Project Name | SQLi SCANNER |
| Course | IKB31603 – Ethical Hacking |
| Attack Category | Web Application Attack |
| Tool Type | SQL Injection Scanner |
| Programming Language | PHP |
| Database | MySQL |
| Local Server | XAMPP (Apache and MySQL) |

---

## 2. Features

- Tests URL GET parameters for possible SQL Injection vulnerabilities.
- Error-based SQL Injection detection.
- Boolean-based SQL Injection detection.
- Time-based SQL Injection detection.
- Displays scan findings and risk assessment.
- Provides scan history.
- Generates downloadable CSV reports.
- Includes administrator login authentication.
- Restricts scanning to localhost and private-network targets.

---

## 3. Repository Structure

```text
SQLi-Scanner/
│
├── assets/
│   └── screenshots/
│       ├── xampp-control-panel.png
│       ├── phpmyadmin-database.png
│       ├── ngrok-command.png
│       └── ngrok-public-url.png
│
├── auth.php
├── index.php
├── login.php
├── logout.php
├── history.php
├── report.php
├── vuln.php
├── setup.sql
│
├── README.md
├── LICENSE
└── .gitignore
```

### Source Code Description

| File | Description |
|---|---|
| `index.php` | Main dashboard, SQL Injection scanning logic, target validation and risk assessment. |
| `auth.php` | Handles authentication functions and PHP sessions. |
| `login.php` | Provides administrator account setup and login functionality. |
| `logout.php` | Ends the current user session. |
| `history.php` | Displays previous scan history. |
| `report.php` | Displays individual scan reports and CSV export. |
| `vuln.php` | Intentionally vulnerable PHP application used as a testing target. |
| `setup.sql` | Creates the MySQL database, users table and sample records. |

---

## 4. Detection Techniques

### 4.1 Error-based Detection

The scanner inserts test characters such as single quotes, double quotes and backslashes into URL parameters.

It checks the response for known SQL error messages.

### 4.2 Boolean-based Detection

The scanner sends TRUE and FALSE conditions to the target application.

It compares the response lengths to identify differences in application behaviour.

### 4.3 Time-based Detection

The scanner sends a test payload containing `SLEEP(3)`.

It measures the response time and checks whether the request takes longer than the normal baseline request.

> Detection results are indicators only. Response length and timing can be affected by application behaviour and network conditions.

---

## 5. Requirements

- Windows Operating System
- XAMPP
- Apache Web Server
- MySQL Database
- PHP with cURL extension enabled
- Web Browser
- ngrok (optional)

---

## 6. Installation and Setup

### Step 1: Start XAMPP

1. Open XAMPP Control Panel.
2. Click **Start** for Apache.
3. Click **Start** for MySQL.
4. Make sure both services are running.

<img width="833" height="535" alt="WhatsApp Image 2026-11-26 at 8 17 30 PM" src="https://github.com/user-attachments/assets/ec3feab9-25d0-49e2-a8c9-30eb441d401c" />


### Step 2: Place the Project in htdocs

1. Download or clone this repository.
2. Copy the project folder into:

```text
C:\xampp\htdocs\SQLi-Scanner
```

3. Make sure all PHP and SQL files are inside the project folder.

### Step 3: Configure the Database

1. Open phpMyAdmin:

```text
http://localhost/phpmyadmin
```

2. Select the **Import** tab.
3. Choose the `setup.sql` file.
4. Click **Import** or **Go**.
5. Confirm that the `sqli_lab` database and `users` table have been created.

The SQL script creates a sample database for the vulnerable demonstration application.

<img width="1600" height="869" alt="WhatsApp Image 2026-11-26 at 8 18 37 PM" src="https://github.com/user-attachments/assets/02fa5564-91ec-44a0-ab08-8548f0f0e1d5" />


### Step 4: Open SQLi SCANNER

Open the following URL in your browser:

```text
http://localhost/SQLi-Scanner/index.php
```

The local vulnerable demonstration application can be accessed using:

```text
http://localhost/SQLi-Scanner/vuln.php?id=1
```

### Step 5: Create an Administrator Account

On the first visit, the application provides an administrator account setup page.

1. Enter a username.
2. Enter an email address.
3. Create a password.
4. Confirm the password.
5. Submit the form.

The account information is stored locally by the application.

---

## 7. Optional: Public Demonstration Using ngrok

ngrok is used to create a temporary public forwarding URL for accessing a local web server.

### Steps

1. Make sure Apache is running in XAMPP.
2. Open Command Prompt in the ngrok installation folder.
3. Run the following command:

```bash
ngrok http 80
```

4. ngrok will generate a forwarding URL.
5. Open the HTTPS forwarding URL in a browser to access the local website through the tunnel.

<img width="963" height="258" alt="WhatsApp Image 2026-11-26 at 8 21 28 PM" src="https://github.com/user-attachments/assets/a3ba7fcd-ddf5-40c3-96a8-bafe0eed3bc6" />


<img width="1481" height="486" alt="WhatsApp Image 2026-11-26 at 8 24 28 PM" src="https://github.com/user-attachments/assets/16325005-5506-432c-b571-38e1494b49ca" />
 


**Security Warning:**

- Use ngrok only for a short and controlled demonstration.
- Do not expose phpMyAdmin or database administration pages publicly.
- Do not expose sensitive information, credentials or session cookies.
- Stop the tunnel using `Ctrl + C` after the demonstration.
- Do not use the public ngrok URL as a scan target. SQLi SCANNER is designed to restrict scanning to local/private lab targets.

---

## 8. How to Use the Scanner

1. Start Apache and MySQL in XAMPP.
2. Open SQLi SCANNER in your browser.
3. Log in using the administrator account.
4. Enter an authorized lab URL containing a GET parameter.
5. Provide a required session cookie through the local scanner interface, if necessary.
6. Start the scan.
7. Review the scan findings and risk assessment.
8. Open scan history to review previous scans.
9. Export the scan report as a CSV file if required.

Example testing URL:

```text
http://localhost/SQLi-Scanner/vuln.php?id=1
```

The parameter `id=1` is a normal baseline input. It is not, by itself, an SQL Injection payload.

---

## 9. Attack Lifecycle Mapping

| Attack Lifecycle Stage | SQLi SCANNER Implementation |
|---|---|
| Reconnaissance | Identifies the authorized target URL and available GET parameters. |
| Scanning | Sends controlled test requests to supported parameters. |
| Vulnerability Identification | Checks for SQL error messages, response differences and unusual delays. |
| Analysis | Evaluates scan findings and calculates a risk score. |
| Reporting | Displays scan results, scan history and downloadable CSV reports. |

SQLi SCANNER focuses on identifying possible SQL Injection indicators. It does not perform database data extraction.

---

## 10. Ethical Considerations

### Authorization and Scope

- Obtain explicit permission before testing any system.
- Only test localhost, private lab environments or systems with documented authorization.
- Do not scan public websites or third-party systems without written permission.

### Legal Disclaimer

This tool is developed for educational and authorized security testing purposes only.

Unauthorized access or testing may violate applicable laws, including Malaysia's Computer Crimes Act 1997 (Act 563).

Users are responsible for obtaining proper authorization and complying with applicable laws and institutional requirements.

### Rules of Engagement (RoE)

**Authorized Scope**
- Localhost environments.
- Intentionally vulnerable lab applications.
- Other targets with documented permission.

**Testing Window**
- Testing must only be performed during the approved time period.

**Permitted Techniques**
- Error-based detection.
- Boolean-based detection.
- Time-based detection.

**Prohibited Actions**
- Unauthorized scanning.
- Denial-of-service attacks.
- Data extraction.
- Destructive testing.
- Accessing data outside the approved scope.

**Data Handling**
- Do not submit real credentials or sensitive information.
- Keep required testing output locally.
- Do not publish account information or session cookies.

**Emergency Stop**
- Stop the scan immediately if unexpected behaviour occurs.
- Stop the ngrok tunnel using `Ctrl + C` when it is no longer required.

### Responsible Disclosure

If a vulnerability is discovered during an authorized assessment, report it privately to the system owner or designated lecturer.

The report should include:
- Affected URL.
- Vulnerable parameter.
- Observed behaviour.
- Testing date and time.
- Relevant evidence.

Do not publicly disclose vulnerability details without appropriate permission.

---

## 11. Limitations

- The scanner currently supports GET query parameters only.
- POST parameters are not supported.
- Boolean-based detection mainly relies on response-length comparison.
- Time-based detection uses a single timing comparison.
- Network delays may affect detection accuracy.
- SQL error signature matching may not detect every database configuration.
- False positives and false negatives are possible.
- A low-risk result does not guarantee that the application is secure.

---

## 12. Future Improvements

- Add POST parameter scanning.
- Improve boolean-based detection accuracy.
- Perform repeated time-based tests.
- Improve vulnerability evidence and confidence levels.
- Add more database error signatures.
- Improve report generation and scan configuration.

---

## 13. License

This project is released under the MIT License.

See the [LICENSE](LICENSE) file for more information.

---

**Course:** IKB31603 – Ethical Hacking  
**Project:** SQLi SCANNER
