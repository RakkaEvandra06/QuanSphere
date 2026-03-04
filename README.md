<img width="1114" height="228" alt="ascii-art-text (zerotracer)" src="https://github.com/user-attachments/assets/2884d2e9-b0e1-4f79-82b0-892632b97d69" />

# 🔐 ZeroTracer v3 - Hardened Crypto Toolkit

ZeroTrace v3 is a hardened cryptography toolkit engineered for secure data encryption built in Python.  
It supports AES-GCM, RSA-OAEP, Hybrid Encryption, Digital Signature (RSA-PSS), and SHA hashing.

---

## 📦 Repository Structure

```bash
zerotracer/
│
├── .gitignore
├── requirements.txt
├── zerotracer.py
└── README.md
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
```

---

## 🎯 Install the required package
Run:
```bash
pip3 install pycryptodome
```

If you're on Kali Linux:
```bash
sudo apt install python3-pycryptodome
```

## 🚀 Usage

🔑 Generate RSA Key Pair
```bash
python zerotracer.py genrsa
```
Output:
private.pem
public.pem

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