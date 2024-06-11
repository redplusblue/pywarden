import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import pickle

def derive_key(password):
    # Derive a key from a password
    salt = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
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
    def __init__(self, root):
        self.root = root
        self.root.title("PyWarden")
        self.key = None
        self.entries = []

        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack()

        self.label = tk.Label(self.login_frame, text="Password")
        self.label.pack()
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.pack()
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.authenticate)
        self.login_button.pack()

    def authenticate(self):
        self.key = derive_key(self.password_entry.get())
        self.login_frame.destroy()

        if os.path.exists("passwords.txt"):
            with open("passwords.txt", "rb") as f:
                encrypted_data = f.read()
            try:
                self.entries = decrypt_data(self.key, encrypted_data)
            except:
                messagebox.showerror("Error", "Incorrect password. Exiting.")
                self.root.destroy()
                return
        else:
            with open("passwords.txt", "wb") as f:
                f.write(b'')

        self.create_main_screen()

    def create_main_screen(self):
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack()

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack()

        self.logins_frame = tk.Frame(self.notebook)
        self.secure_notes_frame = tk.Frame(self.notebook)

        self.notebook.add(self.logins_frame, text="Logins")
        self.notebook.add(self.secure_notes_frame, text="Secure Notes")

        self.create_logins_screen()
        self.create_secure_notes_screen()

    def create_logins_screen(self):
        self.logins_tree = ttk.Treeview(self.logins_frame)
        self.logins_tree['columns'] = ('name', 'website', 'username', 'password', 'notes')
        self.logins_tree.column("#0", width=0, stretch=tk.NO)
        self.logins_tree.column('name', anchor=tk.W, width=100)
        self.logins_tree.column('website', anchor=tk.W, width=100)
        self.logins_tree.column('username', anchor=tk.W, width=100)
        self.logins_tree.column('password', anchor=tk.W, width=100)
        self.logins_tree.column('notes', anchor=tk.W, width=100)
        self.logins_tree.heading('#0', text="", anchor=tk.W)
        self.logins_tree.heading('name', text="Name", anchor=tk.W)
        self.logins_tree.heading('website', text="Website", anchor=tk.W)
        self.logins_tree.heading('username', text="Username", anchor=tk.W)
        self.logins_tree.heading('password', text="Password", anchor=tk.W)
        self.logins_tree.heading('notes', text="Notes", anchor=tk.W)
        self.logins_tree.pack()

        self.logins_button_frame = tk.Frame(self.logins_frame)
        self.logins_button_frame.pack()

        self.add_login_button = tk.Button(self.logins_button_frame, text="Add Login", command=self.add_login)
        self.add_login_button.pack(side=tk.LEFT)

        self.delete_login_button = tk.Button(self.logins_button_frame, text="Delete Login", command=self.delete_login)
        self.delete_login_button.pack(side=tk.LEFT)

        for i, entry in enumerate(self.entries):
            if entry['type'] == 'login':
                self.logins_tree.insert('', 'end', values=(entry['name'], entry['website'], entry['username'], entry['password'], entry['notes']))

    def create_secure_notes_screen(self):
        self.secure_notes_tree = ttk.Treeview(self.secure_notes_frame)
        self.secure_notes_tree['columns'] = ('title', 'content')
        self.secure_notes_tree.column("#0", width=0, stretch=tk.NO)
        self.secure_notes_tree.column('title', anchor=tk.W, width=100)
        self.secure_notes_tree.column('content', anchor=tk.W, width=100)
        self.secure_notes_tree.heading('#0', text="", anchor=tk.W)
        self.secure_notes_tree.heading('title', text="Title", anchor=tk.W)
        self.secure_notes_tree.heading('content', text="Content", anchor=tk.W)
        self.secure_notes_tree.pack()

        self.secure_notes_button_frame = tk.Frame(self.secure_notes_frame)
        self.secure_notes_button_frame.pack()

        self.add_secure_note_button = tk.Button(self.secure_notes_button_frame, text="Add Secure Note", command=self.add_secure_note)
        self.add_secure_note_button.pack(side=tk.LEFT)

        self.delete_secure_note_button = tk.Button(self.secure_notes_button_frame, text="Delete Secure Note", command=self.delete_secure_note)
        self.delete_secure_note_button.pack(side=tk.LEFT)

        for i, entry in enumerate(self.entries):
            if entry['type'] == 'secure_note':
                self.secure_notes_tree.insert('', 'end', values=(entry['title'], entry['content']))

    def add_login(self):
        self.add_login_window = tk.Toplevel(self.root)
        self.add_login_window.title("Add Login")

        self.add_login_name_label = tk.Label(self.add_login_window, text="Name")
        self.add_login_name_label.pack()
        self.add_login_name_entry = tk.Entry(self.add_login_window)
        self.add_login_name_entry.pack()

        self.add_login_website_label = tk.Label(self.add_login_window, text="Website")
        self.add_login_website_label.pack()
        self.add_login_website_entry = tk.Entry(self.add_login_window)
        self.add_login_website_entry.pack()

        self.add_login_username_label = tk.Label(self.add_login_window, text="Username")
        self.add_login_username_label.pack()
        self.add_login_username_entry = tk.Entry(self.add_login_window)
        self.add_login_username_entry.pack()

        self.add_login_password_label = tk.Label(self.add_login_window, text="Password")
        self.add_login_password_label.pack()
        self.add_login_password_entry = tk.Entry(self.add_login_window, show="*")
        self.add_login_password_entry.pack()

        self.add_login_notes_label = tk.Label(self.add_login_window, text="Notes")
        self.add_login_notes_label.pack()
        self.add_login_notes_entry = tk.Entry(self.add_login_window)
        self.add_login_notes_entry.pack()

        self.add_login_button = tk.Button(self.add_login_window, text="Add Login", command=self.save_login)
        self.add_login_button.pack()

    def save_login(self):
        self.entries.append({
            'type': 'login',
            'name': self.add_login_name_entry.get(),
            'website': self.add_login_website_entry.get(),
            'username': self.add_login_username_entry.get(),
            'password': self.add_login_password_entry.get(),
            'notes': self.add_login_notes_entry.get(),
        })

        self.logins_tree.insert('', 'end', values=(self.add_login_name_entry.get(), self.add_login_website_entry.get(), self.add_login_username_entry.get(), self.add_login_password_entry.get(), self.add_login_notes_entry.get()))

        self.add_login_window.destroy()
        self.save_data()

    def add_secure_note(self):
        self.add_secure_note_window = tk.Toplevel(self.root)
        self.add_secure_note_window.title("Add Secure Note")

        self.add_secure_note_title_label = tk.Label(self.add_secure_note_window, text="Title")
        self.add_secure_note_title_label.pack()
        self.add_secure_note_title_entry = tk.Entry(self.add_secure_note_window)
        self.add_secure_note_title_entry.pack()

        self.add_secure_note_content_label = tk.Label(self.add_secure_note_window, text="Content")
        self.add_secure_note_content_label.pack()
        self.add_secure_note_content_entry = tk.Entry(self.add_secure_note_window)
        self.add_secure_note_content_entry.pack()

        self.add_secure_note_button = tk.Button(self.add_secure_note_window, text="Add Secure Note", command=self.save_secure_note)
        self.add_secure_note_button.pack()

    def save_secure_note(self):
        self.entries.append({
            'type': 'secure_note',
            'title': self.add_secure_note_title_entry.get(),
            'content': self.add_secure_note_content_entry.get(),
        })

        self.secure_notes_tree.insert('', 'end', values=(self.add_secure_note_title_entry.get(), self.add_secure_note_content_entry.get()))

        self.add_secure_note_window.destroy()
        self.save_data()

    def delete_login(self):
        selected_item = self.logins_tree.selection()[0]
        self.logins_tree.delete(selected_item)
        self.save_data()

    def delete_secure_note(self):
        selected_item = self.secure_notes_tree.selection()[0]
        self.secure_notes_tree.delete(selected_item)
        self.save_data()

    def save_data(self):
        encrypted_data = encrypt_data(self.key, self.entries)
        with open("passwords.txt", "wb") as f:
            f.write(encrypted_data)

root = tk.Tk()
app = PasswordManager(root)
root.mainloop()