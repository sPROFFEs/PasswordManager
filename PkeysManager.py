# main.py
import sqlite3
import os
import string
import random
import hashlib
import base64
import pyperclip
import time
import threading
import ttkbootstrap as ttk
from PIL import Image, ImageTk
from ttkbootstrap.constants import *
from tkinter import simpledialog, messagebox, PhotoImage
from cryptography.fernet import Fernet

# Funciones de cifrado y base de datos

def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.urlsafe_b64encode(key), salt

def save_key(key, salt):
    with open("key.key", "wb") as key_file:
        key_file.write(key + b"::" + salt)

def load_key():
    with open("key.key", "rb") as key_file:
        key, salt = key_file.read().split(b"::")
    return key, salt

def encrypt_message(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()

def init_db():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                      (id INTEGER PRIMARY KEY, service TEXT, username TEXT, password TEXT, group_name TEXT)''')
    conn.commit()
    conn.close()

def store_password(service_name, username, password, key, group='General'):
    encrypted_password = encrypt_message(password, key)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (service, username, password, group_name) VALUES (?, ?, ?, ?)",
                   (service_name, username, encrypted_password, group))
    conn.commit()
    conn.close()

def retrieve_password(service_id, key):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM passwords WHERE id=?", (service_id,))
    result = cursor.fetchone()
    conn.close()
    if result:
        return decrypt_message(result[0], key)
    return None

def update_password(service_id, new_password, key, group='General'):
    encrypted_password = encrypt_message(new_password, key)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE passwords SET password=?, group_name=? WHERE id=?", (encrypted_password, group, service_id))
    conn.commit()
    conn.close()

def delete_password(service_id):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id=?", (service_id,))
    conn.commit()
    conn.close()

def list_services(group_name=None):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    if group_name and group_name != "All":
        cursor.execute("SELECT id, service, username, group_name FROM passwords WHERE group_name=?", (group_name,))
    else:
        cursor.execute("SELECT id, service, username, group_name FROM passwords")
    services = cursor.fetchall()
    conn.close()
    return services

def list_groups():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT group_name FROM passwords")
    groups = cursor.fetchall()
    conn.close()
    return [group[0] for group in groups]

def generate_secure_password():
    length = simpledialog.askinteger("Length of the password (8-64)", "Enter the length of the password (between 8 and 64):", minvalue=8, maxvalue=64)
    if length is None:
        return None

    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def initialize_password_manager():
    try:
        if not os.path.exists("key.key"):
            password = simpledialog.askstring("Password", "Enter a password to encrypt the database:", show='*')
            if not password:
                messagebox.showerror("Error", "The password cannot be blank.")
                return None
            key, salt = derive_key(password)
            save_key(key, salt)
            init_db()
        else:
            password = simpledialog.askstring("Password", "Enter the password to decrypt the database:", show='*')
            key, salt = load_key()
            derived_key, _ = derive_key(password, salt)
            if derived_key != key:
                messagebox.showerror("Error", "Incorrect password.")
                return None
            key = derived_key
        return key
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return None

# Funciones GUI

def add_password():
    service_name = simpledialog.askstring("Service Name", "Enter the name of the service:")
    if not service_name:
        messagebox.showerror("Error", "The service name cannot be blank.")
        return

    username = simpledialog.askstring("Username", "Enter the username for the service:")
    if not username:
        messagebox.showerror("Error", "The username cannot be blank.")
        return

    if messagebox.askyesno("Group", "Do you want to create a new group?"):
        group_name = simpledialog.askstring("Group Name", "Enter the new group name:")
        if not group_name:
            messagebox.showerror("Error", "The group name cannot be blank.")
            return
    else:
        groups = list_groups()
        if not groups:
            messagebox.showerror("Error", "No groups available. Please create a new group.")
            return
        group_name = select_group_dialog(groups)
        if not group_name:
            messagebox.showerror("Error", "The group name cannot be blank.")
            return

    generate_secure = messagebox.askyesno("Generate Secure Password", "Do you want to generate a secure password?")
    if generate_secure:
        password = generate_secure_password()
    else:
        password = simpledialog.askstring("Password", "Enter the password:", show='*')

    if not password:
        messagebox.showerror("Error", "The password cannot be blank.")
        return

    store_password(service_name, username, password, key, group_name)
    messagebox.showinfo("Success", f"Password for {service_name} saved successfully.")

def select_group_dialog(groups):
    group_name = None

    def on_select_group():
        nonlocal group_name
        group_name = group_var.get()
        dialog.destroy()

    dialog = ttk.Toplevel()
    dialog.title("Select Group")

    group_var = ttk.StringVar()
    group_var.set(groups[0])

    ttk.Label(dialog, text="Select an existing group:").pack(padx=20, pady=5)
    group_menu = ttk.OptionMenu(dialog, group_var, *groups)
    group_menu.pack(padx=20, pady=5)

    ttk.Button(dialog, text="Select", command=on_select_group).pack(padx=20, pady=10)
    dialog.wait_window()

    return group_name

def show_password(service_id):
    password = retrieve_password(service_id, key)
    if password:
        root = ttk.Toplevel()
        root.title("Password")

        ttk.Label(root, text=f"The password for service ID {service_id} is:").pack(padx=20, pady=10)

        text_widget = ttk.Text(root, height=1, width=40)
        text_widget.insert("1.0", password)
        text_widget.pack(padx=20, pady=10)
        text_widget.config(state="disabled")

        scrollbar = ttk.Scrollbar(root, command=text_widget.yview)
        scrollbar.pack(side="right", fill="y")
        text_widget.config(yscrollcommand=scrollbar.set)

        def copy_to_clipboard():
            pyperclip.copy(password)
            root.destroy()
            threading.Thread(target=clear_clipboard_after_timeout).start()

        def clear_clipboard_after_timeout():
            time.sleep(5)
            pyperclip.copy("")

        copy_button = ttk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
        copy_button.pack(padx=20, pady=10)

        root.mainloop()
    else:
        messagebox.showerror("Error", "Password not found for the specified service ID.")

def update_password_gui(service_id):
    if not service_id:
        messagebox.showerror("Error", "The service ID cannot be blank.")
        return

    confirm = messagebox.askyesno("Update Password", f"Are you sure you want to update the password for service ID {service_id}?")
    if not confirm:
        return

    new_password = simpledialog.askstring("New Password", "Enter the new password:", show='*')
    if not new_password:
        messagebox.showerror("Error", "The new password cannot be blank.")
        return

    group_name = simpledialog.askstring("Group Name", "Enter the group name (default is 'General'):", initialvalue="General")
    if not group_name:
        group_name = "General"

    update_password(service_id, new_password, key, group_name)
    messagebox.showinfo("Success", f"Password for service ID {service_id} updated successfully.")

def delete_password_gui(service_id):
    if not service_id:
        messagebox.showerror("Error", "The service ID cannot be blank.")
        return

    confirm = messagebox.askyesno("Delete Password", f"Are you sure you want to delete the password for service ID {service_id}?")
    if confirm:
        delete_password(service_id)
        messagebox.showinfo("Success", f"Password for service ID {service_id} deleted successfully.")

def list_services_gui():
    groups = list_groups()
    groups.insert(0, "All")

    def on_select_group(event=None):
        selected_group = group_var.get()
        services = list_services(selected_group)
        show_services(services)

    def on_vertical_scroll(*args):
        services_canvas.yview(*args)

    root = ttk.Window(themename="darkly")
    root.title("Password Manager")

    main_frame = ttk.Frame(root, padding=20)
    main_frame.grid(row=0, column=0, sticky="nsew")

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    ttk.Label(main_frame, text="List of Services", font=("Tahoma", 16)).grid(row=0, column=0, columnspan=7, pady=10, sticky="ew")

    ttk.Label(main_frame, text="Group:").grid(row=1, column=0, sticky="w")

    group_var = ttk.StringVar()
    group_var.set(groups[0])
    group_menu = ttk.OptionMenu(main_frame, group_var, *groups, command=on_select_group)
    group_menu.grid(row=1, column=1, pady=5, sticky="ew")

    ttk.Label(main_frame, text="ID", width=10).grid(row=2, column=0, sticky="ew")
    ttk.Label(main_frame, text="Service", width=20).grid(row=2, column=1, sticky="ew")
    ttk.Label(main_frame, text="Username", width=20).grid(row=2, column=2, sticky="ew")
    ttk.Label(main_frame, text="Group", width=15).grid(row=2, column=3, sticky="ew")

    services_canvas = ttk.Canvas(main_frame)
    services_canvas.grid(row=3, column=0, columnspan=7, pady=10, sticky="nsew")

    scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=services_canvas.yview)
    scrollbar.grid(row=3, column=7, sticky="ns")

    services_frame = ttk.Frame(services_canvas)
    services_frame.bind("<Configure>", lambda e: services_canvas.configure(scrollregion=services_canvas.bbox("all")))
    services_canvas.create_window((0, 0), window=services_frame, anchor='nw')
    services_canvas.configure(yscrollcommand=scrollbar.set)

    main_frame.grid_rowconfigure(3, weight=1)
    main_frame.grid_columnconfigure(0, weight=1)
    main_frame.grid_columnconfigure(1, weight=1)
    main_frame.grid_columnconfigure(2, weight=1)
    main_frame.grid_columnconfigure(3, weight=1)
    main_frame.grid_columnconfigure(4, weight=1)
    main_frame.grid_columnconfigure(5, weight=1)
    main_frame.grid_columnconfigure(6, weight=1)

    def show_services(services):
        for widget in services_frame.winfo_children():
            widget.destroy()

        for index, (service_id, service_name, username, group_name) in enumerate(services):
            ttk.Label(services_frame, text=service_id, width=10).grid(row=index, column=0, sticky="ew")
            ttk.Label(services_frame, text=service_name, width=20).grid(row=index, column=1, sticky="ew")
            ttk.Label(services_frame, text=username, width=20).grid(row=index, column=2, sticky="ew")
            ttk.Label(services_frame, text=group_name, width=15).grid(row=index, column=3, sticky="ew")

            ttk.Button(services_frame, text="Show Password", command=lambda s=service_id: show_password(s)).grid(row=index, column=4, pady=5, sticky="ew")
            ttk.Button(services_frame, text="Update Password", command=lambda s=service_id: update_password_gui(s)).grid(row=index, column=5, pady=5, sticky="ew")
            ttk.Button(services_frame, text="Delete Password", command=lambda s=service_id: delete_password_gui(s)).grid(row=index, column=6, pady=5, sticky="ew")

        for col in range(7):
            services_frame.grid_columnconfigure(col, weight=1)

    services = list_services()
    show_services(services)

    ttk.Button(main_frame, text="Back", width=20, command=root.destroy).grid(row=4, column=0, columnspan=7, pady=10, sticky="ew")
    ttk.Label(main_frame, text="Developed by PR0FF3", font=("Helvetica", 10)).grid(row=5, column=0, columnspan=7, pady=5, sticky="ew")

    root.mainloop()


def change_group_gui(service_id):
    if not service_id:
        messagebox.showerror("Error", "The service ID cannot be blank.")
        return

    new_group = simpledialog.askstring("New Group", f"Enter the new group for service ID {service_id}:")
    if not new_group:
        messagebox.showerror("Error", "The group name cannot be blank.")
        return

    update_password(service_id, retrieve_password(service_id, key), key, new_group)
    messagebox.showinfo("Success", f"Group for service ID {service_id} updated successfully.")

def main_gui():
    global key
    key = initialize_password_manager()
    if not key:
        return

    root = ttk.Window(themename="darkly")
    root.title("Password Manager")

    main_frame = ttk.Frame(root, padding=20)
    main_frame.pack(padx=10, pady=10)

    # Cargar imagen y mostrarla en la parte superior
    image_path = "icon.png"  # Reemplazar con la ruta a tu imagen
    image = Image.open(image_path)
    image = image.resize((400, 125), Image.LANCZOS)  # Redimensionar la imagen
    logo = ImageTk.PhotoImage(image)
    logo_label = ttk.Label(main_frame, image=logo)
    logo_label.image = logo  # Mantener una referencia a la imagen
    logo_label.grid(row=0, column=0, columnspan=2, pady=10)

    ttk.Button(main_frame, text="Add New Password", width=62, command=add_password).grid(row=1, column=0, pady=5)
    ttk.Button(main_frame, text="List Services", width=62, command=list_services_gui).grid(row=2, column=0, pady=5)
    ttk.Button(main_frame, text="Exit", width=62, command=root.quit).grid(row=3, column=0, pady=5)
    ttk.Label(main_frame, text="Developed by PR0FF3", font=("Tahoma", 10)).grid(row=4, column=0, pady=5)

    root.mainloop()

if __name__ == "__main__":
    main_gui()
