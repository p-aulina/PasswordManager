# Simple Password Manager
Password manager with a simple graphical interface, built using Python.Easily store, retrieve, and manage your passwords locally.

## Features
- siple GUI,
- encrypted local password storage,
- encrypted master password to the manager,
- add, view, and delete saved passwords,
- implemented password generator,
- data stored securely in a local file

## Tech Stack
- language: Python
- GUI library: Qt6
- hashing (master password): hashlib (SHA2-256)
- encryption (other passwords): cryptography (Fernet)
- storage - local JSON file

## Usage
On first launch you will be asked to set a master password.
With the use od GUI you can:
- add new password entries (domain, url, username, password) with an option to generate a secure password,
- view existing entries after entering the master password and copy them to your clipboard,
- delete stored entries.
All data is encrypted and saved locally.

## Important notes
- there is no method to recover your master password,
- this password manager is not synchronised with any cloud - it only works locally,
- intended for personal use.