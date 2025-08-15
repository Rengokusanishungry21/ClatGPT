# ClatGPT
A chatbot with many OpenAI LLMs, including GPT-4, GPT-4o, GPT-4-o3, GPT-5, and more. Perfect for people annoyed with the new ChatGPT and lack of models to choose from.
---
# ClatGPT Multi-Model Chatbot v1.00

**ClatGPT** is a secure, multi-model desktop chatbot client for OpenAI’s models, built with Python and Tkinter.
It supports real-time streaming responses, model switching, persistent settings, and **encrypted transcript saving** using **ChaCha20-Poly1305** (256-bit).

This tool is designed for users who want **full control** over their AI chat history, with optional autosave encryption and persistent configuration.
---
## ✨ Features

### 🔹 Multi-Model Support

* Quickly switch between multiple OpenAI models (`GPT-5`, `GPT-4o`, `GPT-4.1`, `GPT-3.5 Turbo`, etc.).
* Model availability check with API verification to prevent unsupported requests.

### 🔹 Secure Transcript Storage

* Save transcripts in **encrypted `.chat` files** using **ChaCha20-Poly1305 (256-bit)** AEAD encryption.
* Open encrypted chats with a user-provided decryption key.
* Generate random secure keys directly from the UI.
* Copy encryption keys to the clipboard.

### 🔹 Encrypted Autosave

* Optional automatic saving of encrypted transcripts at regular intervals.
* Change autosave encryption keys at any time.
* Prevents loss of conversation in the event of a crash.

### 🔹 Persistent Settings

* Saves your:

  * Last selected model
  * System prompts per model
  * Word wrap preference
  * Temperature setting
  * Autosave configuration
  * Autosave file path
* Settings stored in a JSON config file in platform-specific config directories.

### 🔹 Streaming Responses

* Real-time response streaming from OpenAI’s API.
* Adjustable temperature control (0.0 to 1.0) via slider.
* Hard and stall timeouts to prevent hanging requests.

### 🔹 User Interface

* Modern, clean **Tkinter** interface with:

  * Banner ASCII art
  * Model list panel
  * System prompt editor
  * Chat transcript display
  * Multi-line input field
  * Send/Stop buttons
* Right-click context menus for copy/select-all.
* Keyboard shortcuts:

  * `Ctrl+S` → Save transcript
  * `Ctrl+L` → Clear conversation
  * `Esc` → Stop streaming
---
## 📂 File Formats

| File Type      | Extension | Encryption | Description                                               |
| -------------- | --------- | ---------- | --------------------------------------------------------- |
| Plain Text     | `.txt`    | ❌ No       | Legacy/unsupported in current version                     |
| Encrypted Chat | `.chat`   | ✅ Yes      | ChaCha20-Poly1305-256 with 64-character uppercase hex key |

---

## 🔐 Encryption Details

* **Cipher**: ChaCha20-Poly1305 AEAD
* **Key Size**: 256 bits (64 hexadecimal characters)
* **Nonce Size**: 96 bits (random per encryption)
* **Associated Data**: File header (`CHACHA20-POLY1305-256\n`)
* **Integrity**: Authentication tag verifies content & key validity.

If the wrong key is provided, the app refuses to decrypt and notifies the user.

---
## 🛠 Requirements

* Python **3.8+**
* OpenAI API key
* Internet connection

Dependencies are automatically installed at runtime:

```
openai
cryptography
```
---
## 📦 Installation

1. **Clone this repository or download it**

2. **Run the application**

The script automatically installs missing dependencies on the first run.

---
## ⚙️ Configuration & Settings

* Settings are stored in:

  * **Windows**: `%APPDATA%\ClatGPT\settings.json`
  * **macOS**: `~/Library/Application Support/ClatGPT/settings.json`
  * **Linux**: `~/.config/clatgpt/settings.json`

Example settings file:

```json
{
  "last_model": "GPT-4o",
  "temperature": 0.8,
  "wrap": true,
  "autosave_enabled": true,
  "autosave_path": "/home/user/chat_history/chat.chat",
  "system_prompts": {
    "gpt-4o": "You are a helpful assistant."
  }
}
```

---
## 🔑 Key Management

When saving or opening an encrypted transcript:

* Enter a **256-bit key** (64 uppercase hex characters), or
* Click **Generate Key** for a random secure key.

**Keep your keys safe!**
Without the correct key, decryption is impossible.

---
## 🖥 Usage

1. **Select a model** from the left panel.
2. **(Optional)** Set a custom system prompt.
3. **Type your message** in the input box, and press `Enter` or click **Send**.
4. **Adjust temperature** as needed for creativity vs. precision.
5. **Save** your conversation encrypted for security, or enable **Autosave**.
---
## ⚠️ Security Notes

* The encryption key is **never stored** unless you set it for autosave.
* Losing your key means **permanent loss** of the transcript contents.
* Keep backups of important keys in a password manager.
---
**Author Information
Joshua M Clatney (Clats97)**

Ethical Pentesting Enthusiast

Copyright © 2024-2025 Joshua M Clatney (Clats97) All Rights Reserved

Disclaimer
**DISCLAIMER: This project comes with no warranty, express or implied. The author is not responsible for abuse, misuse, or vulnerabilities. Please use responsibly and ethically in accordance with relevant laws, regulations, legislation and best practices.**
