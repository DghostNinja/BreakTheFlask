
# BreakTheFlask

**BreakTheFlask** contains a list of deliberately vulnerable Flask web application codes designed to help security researchers, ethical hackers, and bug bounty hunters learn and master the **OWASP Top 10** vulnerabilities in a hands-on way.

Whether you're a beginner in application security or prepping for real-world bug bounty hunting, this repo is your playground.

---

## Table of Contents

- [Purpose](#purpose)
- [OWASP Top 10 Covered](#owasp-top-10-covered)
- [Installation](#installation)
- [Usage](#usage)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Purpose

This project simulates real-world insecure coding patterns in Flask to help you:

- Understand OWASP Top 10 vulnerabilities
- Practice exploiting common web application flaws
- Train for bug bounty and CTF-style challenges
- Learn secure coding by contrast

---

## OWASP Top 10 Covered

1. **A01 - Broken Access Control**  
2. **A02 - Cryptographic Failures**  
3. **A03 - Injection (SQL, Command)**  
4. **A04 - Insecure Design**  
5. **A05 - Security Misconfiguration**  
6. **A06 - Vulnerable and Outdated Components**  
7. **A07 - Identification and Authentication Failures**  
8. **A08 - Software and Data Integrity Failures**  
9. **A09 - Security Logging and Monitoring Failures**  
10. **A10 - Server-Side Request Forgery (SSRF)**  

Each vulnerability has a dedicated route, code snippet, and explanation.

---

## Installation

### 1. Clone the repo
```bash
git clone https://github.com/DghostNinja/BreakTheFlask.git
cd BreakTheFlask
```

### 2. Install requirements 
```bash
pip install -r requirements.txt
```


## Usage
```bash
python app.py
```

Open your browser and navigate to:
http://localhost:5000

## Disclaimer

BreakTheFlask is for educational purposes only.
Do not deploy this app to production or use its code in live systems.
Always hack responsibly and within legal boundaries.


## License

MIT License – do what you want, but give credit and don’t be evil.


---
