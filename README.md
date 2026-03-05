<svg width="1200" height="300" xmlns="http://www.w3.org/2000/svg">

  <defs>
    <!-- Animated Gradient -->
    <linearGradient id="bgGradient" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#0f2027">
        <animate attributeName="stop-color" values="#0f2027;#203a43;#2c5364;#0f2027" dur="8s" repeatCount="indefinite"></animate>
      </stop>
      <stop offset="100%" stop-color="#2c5364"></stop>
    </linearGradient>

    <!-- Glow Effect -->
    <filter id="glow">
      <feGaussianBlur stdDeviation="4" result="coloredBlur"></feGaussianBlur>
      <feMerge>
        <feMergeNode in="coloredBlur"></feMergeNode>
        <feMergeNode in="SourceGraphic"></feMergeNode>
      </feMerge>
    </filter>
  </defs>

  <!-- Background -->
  <rect width="1200" height="300" fill="url(#bgGradient)"></rect>

  <!-- Animated Scan Line -->
  <rect x="0" y="0" width="1200" height="5" fill="#00ffd5" opacity="0.6">
    <animate attributeName="y" from="0" to="300" dur="4s" repeatCount="indefinite"></animate>
  </rect>

  <!-- Title -->
  <text x="50%" y="45%" font-size="60" text-anchor="middle" fill="white" font-family="Arial" font-weight="bold" filter="url(#glow)">
    ZeroTrace v4
  </text>

  <!-- Subtitle -->
  <text x="50%" y="65%" font-size="24" text-anchor="middle" fill="#00ffd5" font-family="Arial">
    Hybrid Encryption • Secure File Protection • Enterprise CLI Security Tool
  </text>

</svg>
![download](https://github.com/user-attachments/assets/6a6ce4dd-667d-468e-b540-c669e4dddcfd)

![Security Rating](https://img.shields.io/badge/Security%20Rating-A%2B-brightgreen)
![Encryption](https://img.shields.io/badge/Encryption-AES--256%20%7C%20RSA--4096-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/github/license/RakkaEvandra06/QuanSphere)

---

# 🔐 ZeroTracer v4 - Hardened Crypto Toolkit

ZeroTrace v4 is a hardened cryptography toolkit engineered for secure data encryption built in Python.  
It supports AES-GCM, RSA-OAEP, Hybrid Encryption, Digital Signature (RSA-PSS), and SHA hashing with enhanced security validation..

---

## 📦 Repository Structure

```bash
│
├── .gitignore
├── README.md
├── requirements.txt
└── zerotracer.py
```

---

## ✨ Features

The project demonstrates practical implementation of modern cryptographic standards including:
- AES-256 GCM file encryption/decryption
- RSA-2048 key generation
- RSA-OAEP encryption/decryption
- Hybrid encryption (RSA + AES)
- Digital signature (RSA-PSS)
- SHA256 & SHA512 hashing
- Secure PBKDF2 key derivation

---

## ⚙️ Installation

```bash
git clone https://github.com/RakkaEvandra06/QuanSphere.git
cd QuanSphere
pip install -r requirements.txt
python3 zerotrace.py --help
```

## 🎯 Install the required package

Install pycryptodome for the Version Windows or Linux you're running:
if you're on Windows:
```bash
python pip install pycryptodome
```

If you're on Linux:
```bash
sudo apt install python3-pycryptodome
```

## 🧪 Test Installation

After installing, test:
```bash
python3 -c "from Crypto.Cipher import AES; print('OK')"
```
Output:
If it prints OK, you're good.

## 🚨 If it STILL fails

Quick One-Command Version
```bash
sudo apt install python3-venv -y
python3 -m venv venv
source venv/bin/activate
pip install pycryptodome
python zerotracer.py
```

---

## 🚀 Usage

🔑 Generate RSA Key Pair
```bash
python zerotracer.py genrsa
```

🔐 AES Encryption
Encrypt using password-based key derivation:
```bash
python zerotracer.py aes --encrypt file.txt --out file.enc --password StrongPassword123
```

Encrypt using randomly generated key:
```bash
python zerotracer.py aes --encrypt file.txt --out file.enc --save-key
```

🔓 AES Decryption
```bash
python zerotracer.py aes --decrypt file.enc --out file.txt --password StrongPassword123
```

🔐 RSA Encryption (Short Message)
```bash
python zerotracer.py rsa --encrypt "Sensitive Message" --pub public.pem
```

🔓 RSA Decryption
```bash
python zerotracer.py rsa --decrypt <base64_ciphertext> --priv private.pem
```

🔐 Hybrid Encryption (Recommended for Files)

Encrypt:
```bash
python zerotracer.py hybrid --encrypt document.pdf --out document.qhy --pub public.pem
```

Decrypt:
```bash
python zerotracer.py hybrid --decrypt document.qhy --out document.pdf --priv private.pem
```

✍ Digital Signature
Sign a file:
```bash
python zerotracer.py sign --file file.txt --priv private.pem
```

Verify signature:
```bash
python zerotracer.py sign --verify file.txt --sig file.txt.sig --pub public.pem
```

🧮 Hashing
SHA-256
```bash
python zerotracer.py hash --file file.txt --algo sha256
```

SHA-512
```bash
python zerotracer.py hash --file file.txt --algo sha512
```

---

## ⚠️ Disclaimer

This toolkit is developed for educational and research purposes.

<img width="1140" height="228" alt="ascii-art-text (quansphere)" src="https://github.com/user-attachments/assets/b42c567e-7500-45fe-a900-449d2e8fff56" />
