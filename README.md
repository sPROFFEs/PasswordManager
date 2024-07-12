# PasswordManager
Simple and useful password manager developed on python. Creates a database encrypted by a password, generates secure passwords and save it hashed and salted on the database. If you dont trust the application just look the code and modify it.

## Installation

Install requirements

```bash
  python3 install-requirements.py

```
If it is any issue do it manually

```bash
  pip install cryptography sqlite3 pyperclip colorama

```
Enviroment error bypass (at your own risk)

```bash
  pip install cryptography sqlite3 pyperclip colorama --break-system-packages

```

## Usage/Examples

```bash
python or python3 password-manager.py
```
#### When it first starts, it creates an encrypted database with the password we specify at that moment.
#### The password is not visible so just make sure you know it and then press enter.

![imagen](https://github.com/user-attachments/assets/36c1751d-2742-4b07-a33c-cdfc90d4f62f)

#### Among the available options, we can create, search, modify, delete, and generate passwords.

![imagen](https://github.com/user-attachments/assets/86313d94-1e1c-44ac-9536-8942c543c4f1)

#### If you want to add a new password, you can automatically generate a secure password when creating the entry if not just type one yourself.

![imagen](https://github.com/user-attachments/assets/de09973d-4081-4795-8c2a-db060dca9033)

#### If you want to see the passwords saved on the database select 2

![imagen](https://github.com/user-attachments/assets/157865d9-84c8-4412-85d8-785f50c2050e)

#### The password will appear on top and automatically copied to the clipboard just for 10 senconds, then the clipboard will be deleted
#### You can modify the timeout on the code

![imagen](https://github.com/user-attachments/assets/cb309ee7-f755-4cf3-a2c5-ea5872231738)

#### If you want to modify or delete some entry it will ask you before to ensure your decision

![imagen](https://github.com/user-attachments/assets/a9e3b4df-a4ca-426c-9403-a4675e4c8d1d)
![imagen](https://github.com/user-attachments/assets/5a878caa-06c8-49dd-b4a5-06908d49186e)

#### Finally, you can generate a random password with uppercase letters, lowercase letters, and special characters, with a length between 8 and 64.

![imagen](https://github.com/user-attachments/assets/8ab09f7a-9c1d-4318-8f2a-f91a71b77862)
![imagen](https://github.com/user-attachments/assets/e99b2e63-1878-466b-90df-4484eb974a95)

## Feedback

If you have any feedback, please reach out to us at julioproffessor@gmail.com



