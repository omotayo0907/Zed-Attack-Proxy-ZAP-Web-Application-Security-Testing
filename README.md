### **Security Assessment Using OWASP ZAP on Web Application: Vulnerabilities, Injection Attacks, and Authentication Testing**

---

### **Introduction**

The purpose of this project was to perform a comprehensive security assessment of a target web application using OWASP ZAP. 
The target web application selected was Damn Vulnerable Web App, a vulnerable web app designed specifically for security testing and educational purposes. 
 
The primary goal was to assess the web application’s resilience against common web-based threats and to identify security vulnerabilities, performing injection attacks, and evaluating authentication mechanisms.

---

#### **Tools and Environment**

- **OWASP ZAP**: Open-source tool used for finding security vulnerabilities in web applications.
- **DVWA (Damn Vulnerable Web Application)**: A deliberately insecure PHP/MySQL web application designed for educational purposes.
- **Kali Linux VM**: Operating system for conducting the security test.
- **Browser (Firefox)**: Configured to route traffic through OWASP ZAP’s proxy for monitoring and analysis.
- **Apache2 & MySQL**: Used to host DVWA locally on the Kali Linux machine.

---

#### **3. Project Setup and Configuration**

##### **3.1 Installing and Configuring DVWA**

- DVWA was installed on the local machine using Apache2 and MySQL, creating a suitable environment for testing.
- The setup involved downloading DVWA, moving it to the Apache web directory (`/var/www/html/`), configuring the database, and setting appropriate permissions.
  
**Command to download and unzip DVWA:**
```bash
wget https://github.com/digininja/DVWA/archive/master.zip
unzip master.zip
sudo mv DVWA-master /var/www/html/dvwa
```

- Apache and MySQL services were started, and the DVWA setup was completed by accessing `http://localhost/dvwa/` from the browser.

![dvwa setup](https://github.com/user-attachments/assets/58d3eaef-d683-498e-8a9b-4fc36b06b215)
![dvwa setup2](https://github.com/user-attachments/assets/d5b74e03-266f-489b-bdf3-e5bff429836c)



##### **3.2 Configuring OWASP ZAP**

- OWASP ZAP was installed and configured to proxy all traffic through Firefox, using `127.0.0.1:8080` as the proxy server.
  
**Starting OWASP ZAP:**
```bash
zaproxy &
```
![zap 2](https://github.com/user-attachments/assets/e9b08831-2338-4ad6-bda0-4199bf578db3)

- The browser was configured to direct traffic through ZAP, ensuring that all interactions with DVWA were captured for analysis.

![proxy setting](https://github.com/user-attachments/assets/790f0247-0a62-474c-a277-0ca20a033768)
- The site tree getting populated after the DVWA web app was launched on the browser.
![site tree](https://github.com/user-attachments/assets/5b23c774-acc7-4dbc-930f-af93e185f6bd)

---

#### **4. Testing Methodology**

##### **4.1 Step 1: Passive Spidering and Crawling**

- The **Spidering** feature in OWASP ZAP was used to crawl DVWA and enumerate all accessible pages, forms, and input points, including login forms, search fields, and parameterized URLs.
  
**Procedure:**
1. Right-click on the DVWA URL in the ZAP Sites tree.
2. Select `Attack > Spider`.
3. Configure the spider settings (optional), and click `Start Scan`.
![spidering](https://github.com/user-attachments/assets/99a6b24d-43e8-4530-bcf2-5ca23f4e4c46)


- The spider mapped out the application's structure, including hidden pages and input fields.

![spider result](https://github.com/user-attachments/assets/98dda9f6-032c-42f9-97ef-4dc82e5acf78)


##### **4.2 Step 2: Automated Vulnerability Scanning**

- An **Active Scan** was performed after spidering to automatically test for vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), Command Injection, and others.
  
**Procedure:**
1. Right-click on DVWA in the ZAP Sites tree.
2. Select `Attack > Active Scan`.
3. Configure scan settings and start the scan.
![active scan](https://github.com/user-attachments/assets/19853281-b0d8-407b-bb56-3090ff7a3533)


- The scan resulted in a list of potential vulnerabilities, which were categorized by severity (high, medium, low).

![actve scann](https://github.com/user-attachments/assets/18b9a87c-28e3-4b98-bb79-9c5304e6f217)


---

#### **5. Manual Testing**

##### **5.1 Step 3: Manual SQL Injection Testing**

- SQL Injection was manually tested by injecting SQL payloads such as `' OR '1'='1` into input fields like the login form and URL parameters.
 
**Procedure:**
1. Navigate to the login page of DVWA.
2. In the username or password field, enter an SQL injection payload.
3. Analyze the result of the injection in ZAP’s HTTP request/response logs.

- The test successfully bypassed the authentication mechanism on DVWA’s low security level, allowing unauthorized access to the system.

![sql](https://github.com/user-attachments/assets/71741a6c-f0eb-45c8-8cf0-13046ed6ed74)


##### **5.2 Step 4: Cross-Site Scripting (XSS) Testing**

- Both **reflected XSS** and **stored XSS** vulnerabilities were tested by injecting malicious JavaScript payloads into form fields (e.g., comment fields, search inputs).

**Procedure:**
1. Enter `<script>alert('XSS')</script>` into various input fields.
2. Observe if the script executes, indicating a vulnerability.

- In DVWA, both reflected and stored XSS vulnerabilities were successfully exploited, allowing the execution of arbitrary JavaScript in the user’s browser.

![xss](https://github.com/user-attachments/assets/5408412d-c15a-4fcd-9a7b-a251da3f3eac)


---

#### **6. Authentication Testing**

##### **6.1 Step 5: Testing for Authentication Bypass**

- The DVWA login system was evaluated by attempting to bypass authentication controls using SQL injection and other common attack vectors.

**Procedure:**
1. Submit SQL injection payloads during the login process (e.g., `' OR '1'='1`).
2. ZAP was used to capture and analyze the login request/response traffic.

- The login page was vulnerable to SQL injection, allowing unauthorized access at lower security levels.

![sqll](https://github.com/user-attachments/assets/cde6c027-02db-4708-9034-036a94fe8403)


---

#### **7. Analysis and Results**

- The vulnerabilities identified during both automated and manual tests were analyzed based on severity, impact, and exploitability. 

**Key Findings:**
- **SQL Injection**: Critical vulnerability allowing bypass of authentication.
- **Cross-Site Scripting (XSS)**: High-severity vulnerabilities in multiple input fields.
- **Weak Authentication**: No proper validation or protection against SQL injection on login fields.
![exx](https://github.com/user-attachments/assets/2b8c0480-9bc4-4c8e-88e9-1d051b66170b)



---

#### **8. Conclusion and Recommendations**

The security assessment on DVWA using OWASP ZAP revealed significant vulnerabilities, primarily related to **input validation** and **authentication mechanisms**. These weaknesses could lead to serious security breaches if not addressed. 

**Recommendations**:
1. **Strengthen Input Validation**: Implement server-side input sanitization and validation for all input fields.
2. **Use Parameterized Queries**: Replace dynamically generated SQL queries with parameterized queries to prevent SQL Injection.
3. **Increase Authentication Security**: Use secure hashing mechanisms and multi-factor authentication (MFA) to prevent unauthorized access.
4. **Regular Vulnerability Scanning**: Implement routine vulnerability scans with tools like OWASP ZAP to catch security issues early.

---

#### **9. Report Generation**

- After completing the testing, a detailed report was generated using OWASP ZAP’s reporting tool, documenting the identified vulnerabilities, their severity, and remediation suggestions.

![report](https://github.com/user-attachments/assets/016eccca-a401-457e-8cec-a19129d5abb2)
![exx](https://github.com/user-attachments/assets/76bbcf8e-ec51-4fec-a745-88ee88920c64)


