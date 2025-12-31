# SQLi Hunter Pro (SQLi-KSA)

🔍 **Python SQL Injection Exploitation Tool**  
An interactive and advanced Python script designed to detect and exploit SQL injection vulnerabilities in web applications.

---

## 🚀 Overview

**SQLi-KSA is SQL injection Attack .

This repository contains the main script (`SQLi_KSA.py`) along with example screenshots and guidance for usage.

---

## 🧰 Features

✅ Detect SQL Injection vulnerabilities  
✅ Support for GET & POST parameters  
✅ Database enumeration  
✅ Table & column listing  
✅ Dump database data  
✅ Interactive command menu  
✅ Custom SQL queries  
📁 Organized session output folders

![Preview](https://github.com/Brian9111/SQLi-injection-KSA/blob/main/1%20screen%20.png)
![Preview](https://github.com/Brian9111/SQLi-injection-KSA/blob/main/2screen.png)
![Preview](https://github.com/Brian9111/SQLi-injection-KSA/blob/main/3%20screen.png)
---

## ⚙️ Requirements

You need the following to run the tool:

### 📌 System

- Linux / Kali Linux recommended  
- Python 3.6+ installed

### 📦 Python Dependencies

Install with:

```bash
pip install requests colorama
```


##  🛠 External Tools

Make sure you have sqlmap installed:

```bash
sudo apt update
sudo apt install sqlmap
```

## 📥 Installation

Clone the repository and set permissions:
```bash
git clone https://github.com/Brian9111/SQLi-injection-KSA.git
cd SQLi-injection-KSA
chmod +x SQLi_KSA.py
```

## ▶️ Usage
🧪 Run the tool interactively ( The Best Way )
```bash
python3 SQLi_KSA.py
```


You will be prompted to enter a target URL and choose GET or POST parameters for testing.

## 📌 Example Commands
Test GET URL:
```bash 
python3 SQLi_KSA.py -u "https://example.com/page.php?id=1"

Test POST request:
python3 SQLi_KSA.py -u "https://example.com/login.php" -p username -v admin
```
📋 Menu Options

Once the tool detects SQL injection, it provides options such as:
```bash

1. Enumerate Databases
2. Select Database
3. Enumerate Tables
4. Select Table
5. Enumerate Columns
6. Select Columns
7. Dump Data
8. Custom SQL Query
9. File Read Attempt
10. View Extracted Data
0. Exit
```

(Actual options may vary based on script version.)

## 📂 Output

All results are saved into organized folders with timestamps for each scan session, making it easy to review your findings.

## ⚠️ Legal Disclaimer

This tool is meant only for ethical hacking and authorized security testing.
Unauthorized testing against systems you do not own or have permission to test is illegal and prohibited. Always get written consent before testing. 
GitHub
