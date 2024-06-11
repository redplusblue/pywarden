from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from getpass import getpass
import base64
import os
import pickle

def derive_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'encryption',
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(key, data):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(pickle.dumps(data))
    return encrypted_data

def decrypt_data(key, encrypted_data):
    fernet = Fernet(key)
    data = pickle.loads(fernet.decrypt(encrypted_data))
    return data

class PasswordManager:
    def __init__(self):
        self.entries = []
        self.key = None

    def authenticate(self):
        password = getpass("Enter your password: ")
        self.key = derive_key(password)

        if os.path.exists("passwords.txt"):
            with open("passwords.txt", "rb") as f:
                encrypted_data = f.read()
            try:
                self.entries = decrypt_data(self.key, encrypted_data)
            except:
                print("Incorrect password. Exiting.")
                exit(1)
        else:
            with open("passwords.txt", "wb") as f:
                f.write(b'')

    def save_data(self):
        encrypted_data = encrypt_data(self.key, self.entries)
        with open("passwords.txt", "wb") as f:
            f.write(encrypted_data)

    def add_login(self):
        username = input("Enter username: ")
        password = getpass("Enter password: ")
        website = input("Enter website: ")
        name = input("Enter name: ")
        notes = input("Enter notes: ")
        self.entries.append({
            'type': 'login',
            'username': username,
            'password': password,
            'website': website,
            'name': name,
            'notes': notes,
        })
        self.save_data()

    def add_secure_note(self):
        title = input("Enter title: ")
        content = input("Enter content: ")
        self.entries.append({
            'type': 'secure_note',
            'title': title,
            'content': content,
        })
        self.save_data()

    def display_entries(self):
        for entry in self.entries:
            if entry['type'] == 'login':
                print(f"Name: {entry['name']}")
                print(f"Website: {entry['website']}")
                print(f"Username: {entry['username']}")
                print(f"Password: {entry['password']}")
                print(f"Notes: {entry['notes']}")
            elif entry['type'] == 'secure_note':
                print(f"Title: {entry['title']}")
                print(f"Content: {entry['content']}")
            print()

def main():
    manager = PasswordManager()
    manager.authenticate()
    while True:
        print("1. Add Login")
        print("2. Add Secure Note")
        print("3. Display Entries")
        print("4. Quit")
        choice = input("Enter your choice: ")
        if choice == "1":
            manager.add_login()
        elif choice == "2":
            manager.add_secure_note()
        elif choice == "3":
            manager.display_entries()
        elif choice == "4":
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()