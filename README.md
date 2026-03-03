# 🔐 ZeroTrace v3 - Hardened Crypto Toolkit

ZeroTrace v3 is a hardened cryptography toolkit engineered for secure data encryption built in Python.  
It supports AES-GCM, RSA-OAEP, Hybrid Encryption, Digital Signature (RSA-PSS), and SHA hashing.

---

## 📦 Repository Structure

```bash
quansphere/
│
├── .gitignore
├── requirements.txt
├── zerotrace.py
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
git clone https://github.com/RakkaEvandra06/ZeroTrace.git
cd zerotrace
pip install -r requirements.txt
```

---

## 🚀 Usage

🔑 Generate RSA Key Pair
```bash
python zerotrace.py genrsa
```
Output:
private.pem
public.pem

🔐 AES Encryption
Encrypt using password-based key derivation:
```bash
python zerotrace.py aes --encrypt file.txt --out file.enc --password StrongPassword123
```

Encrypt using randomly generated key:
```bash
python zerotrace.py aes --encrypt file.txt --out file.enc --save-key
```

🔓 AES Decryption
```bash
python zerotrace.py aes --decrypt file.enc --out file.txt --password StrongPassword123
```

🔐 RSA Encryption (Short Message)
```bash
python zerotrace.py rsa --encrypt "Sensitive Message" --pub public.pem
```

🔓 RSA Decryption
```bash
python zerotrace.py rsa --decrypt <base64_ciphertext> --priv private.pem
```

🔐 Hybrid Encryption (Recommended for Files)
Encrypt:
```bash
python zerotrace.py hybrid --encrypt document.pdf --out document.qhy --pub public.pem
```

Decrypt:
```bash
python zerotrace.py hybrid --decrypt document.qhy --out document.pdf --priv private.pem
```

✍ Digital Signature
Sign a file:
```bash
python zerotrace.py sign --file file.txt --priv private.pem
```

Verify signature:
```bash
python zerotrace.py sign --verify file.txt --sig file.txt.sig --pub public.pem
```

🧮 Hashing
```bash
python zerotrace.py hash --file file.txt --algo sha256
```

---

## ⚠️ Disclaimer

This toolkit is developed for educational and research purposes.