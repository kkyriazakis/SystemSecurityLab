# System Security Laboratory Projects

This repository contains a collection of system security laboratory assignments covering various aspects of cybersecurity, cryptography, access control, network monitoring, and vulnerability exploitation.

## 📚 Lab Overview

### Lab 1: Classical Cryptography

**Focus**: Implementation of classical encryption algorithms

- **Caesar Cipher**: Implementation with extended 62-character alphabet (0-9, A-Z, a-z)
- **Vigenère Cipher**: Polyalphabetic substitution cipher
- **One-Time Pad (OTP)**: Theoretically unbreakable encryption method
- **Technologies**: C programming, mathematical cryptography

### Lab 2: Modern Cryptography (AES)

**Focus**: Advanced Encryption Standard and authentication

- **AES Encryption/Decryption**: Support for AES-128 and AES-256
- **CMAC Authentication**: Cipher-based Message Authentication Code
- **File Security**: Secure file encryption with integrity verification
- **Technologies**: OpenSSL EVP API, C programming

### Lab 3: Advanced Cryptographic Systems

**Focus**: Extended cryptographic implementations

- Builds upon Lab 2 concepts with additional security features
- Advanced file handling and cryptographic operations
- **Technologies**: OpenSSL, C programming

### Lab 4: Access Control Monitoring System

**Focus**: File system access monitoring and intrusion detection

- **Dynamic Library Injection**: Uses `LD_PRELOAD` to intercept system calls
- **File Access Logging**: Tracks `fopen()`, `fwrite()` operations with timestamps
- **Malicious User Detection**: Identifies users with suspicious access patterns (>7 failed attempts on >7 different files)
- **File Integrity Monitoring**: Tracks file modifications using fingerprints
- **Technologies**: C programming, system calls, shared libraries

### Lab 5: Enhanced Access Control + Ransomware Detection

**Focus**: Advanced threat detection extending Lab 4

- **Ransomware Simulation**: Script that mimics ransomware behavior
- **Pattern Recognition**: Enhanced detection of malicious file access patterns
- **Behavioral Analysis**: Identifies potential ransomware activities
- **Technologies**: C programming, shell scripting, system monitoring

### Lab 6: Network Traffic Analysis

**Focus**: Real-time network packet monitoring and analysis

- **Packet Capture**: Live network interface monitoring using libpcap
- **Protocol Analysis**: TCP/UDP packet inspection and statistics
- **Traffic Statistics**: Flow analysis, byte counting, packet classification
- **Offline Analysis**: Support for analyzing pre-captured pcap files
- **Technologies**: libpcap, C programming, network protocols

### Lab 7: Network Security - Ad Blocking System

**Focus**: Network-based content filtering using iptables

- **Domain-based Blocking**: DNS resolution and IP-based filtering
- **Firewall Rules**: Automatic iptables rule generation
- **Rule Management**: Save, load, and reset firewall configurations
- **Batch Processing**: Bulk domain and IP address blocking
- **Technologies**: Bash scripting, iptables, DNS resolution

### Lab 8: Buffer Overflow Exploitation

**Focus**: Memory corruption vulnerabilities and exploitation techniques

- **Vulnerable Program**: `Greeter.c` with buffer overflow vulnerability
- **Shellcode Development**: Custom payload generation for code execution
- **Stack Manipulation**: EIP overwrite and stack pointer control
- **Exploit Development**: Python-based payload generator
- **Memory Protection Bypass**: Techniques for executable stack exploitation
- **Technologies**: C programming, Assembly, Python, GDB debugging

## 🛠️ Technologies Used

- **Programming Languages**: C, Python, Bash
- **Security Libraries**: OpenSSL, libpcap
- **System Tools**: iptables, GDB, strace
- **Network Analysis**: Wireshark-compatible pcap files
- **Build Systems**: Make, CMake

## 🚀 Getting Started

Each lab directory contains its own build instructions and documentation. Generally:

```bash
# For C projects with Makefile
cd LabX/
make

# For projects with specific build requirements
# Check individual README files in each lab directory
```

## ⚠️ Security Notice

These projects are for educational purposes only. The vulnerability exploitation techniques and security tools should only be used in controlled environments for learning cybersecurity concepts.

## 📝 Author

**Kleanthis Kyriazakis**  
Student ID: 2015030086  
GitHub: kkyriazakis

## 📄 License

This project is for educational use as part of system security coursework.
