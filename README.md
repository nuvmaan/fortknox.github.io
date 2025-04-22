# 🔐 FortKnox - Ultra Secure Password Manager

FortKnox is a modern, open-source password manager built entirely in Python with a beautiful Tkinter GUI. It focuses on strong encryption, intuitive UX, and privacy-first local storage. Perfect for users who want total control over their credentials without syncing to the cloud.

---

## ✨ Features

- 🔐 **Military-grade Encryption** — AES 256-bit with PBKDF2HMAC (600,000 iterations)
- 🔑 **Local Vault** — All data is securely encrypted and stored offline
- 🧠 **Password Generator** — Generate strong, customizable passwords
- 🧪 **Security Audit** — Find weak, old, or duplicate passwords
- 📋 **Clipboard Protection** — Clears clipboard automatically after 30 seconds
- 🚨 **Emergency Lockdown** — Instantly clears all session data from memory
- 📊 **Strength Meter** — Live password strength feedback via zxcvbn
- 📱 **QR Code Export** — Share passwords via QR code (optional)
- 🧩 **Cross-platform** — Works on Windows, macOS, and Linux

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/nuvmaan/FortKnox---Ultra-Secure-Password-Manager.git
cd fortknox
```

### 2. Install Dependencies

> Make sure Python 3.7+ is installed

```bash
pip install -r requirements.txt
```

### 3. Run the App

```bash
python FortKnox.py
```

---

## 🛡️ Security Notice

- Your master password is never stored. 
- All data is encrypted locally using a password-derived key.
- The app **does not** use the internet or send any data anywhere.

---

## 📜 License

MIT License © [Nuvmaan]

---

## 🤝 Contributing

Pull requests are welcome! If you'd like to contribute, fork the repo and make your changes. Please follow clean code practices.

---
