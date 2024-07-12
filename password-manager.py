import sqlite3
import os
import string
import random
import hashlib
import base64
import pyperclip
import getpass
import colorama
import time
from colorama import Fore, Style
from cryptography.fernet import Fernet

# Inicializar colorama (solo necesario en Windows)
colorama.init()

def copy_with_timeout(text):
    timeout = 10
    # Copiar texto al portapapeles
    pyperclip.copy(text)

    # Esperar durante el tiempo especificado
    time.sleep(timeout)

    # Borrar el portapapeles copiando una cadena vacía
    pyperclip.copy("")
 
# Derivar la clave Fernet desde la contraseña del usuario
def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.urlsafe_b64encode(key), salt

# Guardar la clave y sal
def save_key(key, salt):
    with open("key.key", "wb") as key_file:
        key_file.write(key + b"::" + salt)

# Cargar la clave y sal
def load_key():
    with open("key.key", "rb") as key_file:
        key, salt = key_file.read().split(b"::")
    return key, salt

# Cifrar un mensaje
def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

# Descifrar un mensaje
def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message).decode()
    return decrypted_message

# Hash y salt de una contraseña
def hash_and_salt_password(password):
    salt = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    password_with_salt = password + salt
    hashed_password = hashlib.sha256(password_with_salt.encode()).hexdigest()
    return hashed_password, salt

# Crear base de datos y tabla
def init_db():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                      (service TEXT, password TEXT, salt TEXT)''')
    conn.commit()
    conn.close()

# Guardar contraseña
def store_password(service, password, key):
    # Primero, verificar si el servicio ya existe en la base de datos
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM passwords WHERE service=?", (service,))
    count = cursor.fetchone()[0]
    conn.close()

    if count > 0:
        print(f"A password for {service} already exists. Please choose another service name.")
        return

    # Si el servicio no existe, proceder a guardar la contraseña
    encrypted_password = encrypt_message(password, key)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (service, password, salt) VALUES (?, ?, ?)", (service, encrypted_password, ''))
    conn.commit()
    conn.close()
    

# Recuperar contraseña
def retrieve_password(service, key):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM passwords WHERE service=?", (service,))
    result = cursor.fetchone()
    conn.close()
    if result:
        encrypted_password = result[0]
        decrypted_password = decrypt_message(encrypted_password, key)
        return decrypted_password
    else:
        return None

# Modificar contraseña
def update_password(service, new_password, key):
    encrypted_password = encrypt_message(new_password, key)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE passwords SET password=? WHERE service=?", (encrypted_password, service))
    conn.commit()
    conn.close()

# Eliminar contraseña
def delete_password(service):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE service=?", (service,))
    conn.commit()
    conn.close()

# Listar todos los servicios
def list_services():
    clear()
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute("SELECT service FROM passwords")
    services = cursor.fetchall()
    conn.close()
    return [service[0] for service in services]

# Generar una contraseña segura
def generate_secure_password():
    while True:
        try:
            length = int(input("Enter the length of the password (8-64): "))
            if length < 8 or length > 64:
                clear()
                print("Length must be between 8 and 64 characters.")
                continue
            break
        except ValueError:
            clear()
            print("Invalid input. Please enter a valid number.")

    characters = string.ascii_letters + string.digits + string.punctuation
    secure_password = ''.join(random.choice(characters) for _ in range(length))
    return secure_password

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# Mostrar el menú de opciones
def print_menu():
    print(f"""{Fore.GREEN}
                                                                                                                        
,------.                                                   ,--.,--.   ,--.                                              
|  .--. ' ,--,--. ,---.  ,---. ,--.   ,--. ,---. ,--.--. ,-|  ||   `.'   | ,--,--.,--,--,  ,--,--. ,---.  ,---. ,--.--. 
|  '--' |' ,-.  |(  .-' (  .-' |  |.'.|  || .-. ||  .--'' .-. ||  |'.'|  |' ,-.  ||       ' ,-.  || .-. || .-. :|  .--' 
|  | --'   '-'  |.-'  `).-'  `)|   .'.   |' '-' '|  |     `-' ||  |   |  |  '-'  ||  ||  |  '-'  |' '-' '    --.|  |    
`--'      `--`--'`----' `----' '--'   '--' `---' `--'    `---' `--'   `--' `--`--'`--''--' `--`--'.`-  /  `----'`--'    
                                                                                                  `---'{Style.RESET_ALL} v0.1 by PR0FF3""")
    print("1. Add new password")
    print("2. Search password")
    print("3. Modify password")
    print("4. Delete password")
    print("5. Generate secure password")
    print("6. Salir")

# Mostrar el menú de servicios
def print_services(services):
    print("\nServices:")
    for i, service in enumerate(services, 1):
        print(f"{i}. {service}")
    print("0. Cancel")

# Seleccionar un servicio
def select_service():
    services = list_services()
    if not services:
        print("No stored services.")
        return None

    print_services(services)
    choice = int(input("Choose a service: "))
    if choice == 0:
        clear()
        return None
    elif 1 <= choice <= len(services):
        return services[choice - 1]
    else:
        print("Invalid option.")
        return None

# Inicialización del gestor de contraseñas
def initialize_password_manager():
        try:
            print("""
                    8888888b.                                                                 888       888b     d888                                                      
                    888   Y88b                                                                888       8888b   d8888                                                      
                    888    888                                                                888       88888b.d88888                                                      
                    888   d88P  8888b.  .d8888b  .d8888b  888  888  888  .d88b.  888d888  .d88888       888Y88888P888  8888b.  88888b.   8888b.   .d88b.   .d88b.  888d888 
                    8888888P        88b 88K      88K      888  888  888 d88  88b 888P    d88  888       888 Y888P 888      88b 888  88b      88b d88P 88b d8P  Y8b 888P    
                    888        .d888888 Y8888b.   Y8888b. 888  888  888 888  888 888     888  888       888  Y8P  888 .d888888 888  888 .d888888 888  888 88888888 888     
                    888        888  888      X88      X88 Y88b 888 d88P Y88..88P 888     Y88b 888       888      888 888  888 888  888 888  888 Y88b 888 Y8b.     888     
                    888         Y888888  88888P   88888P    Y8888888P     Y88P   888       Y88888       888       888  Y888888 888  888  Y888888   Y88888   Y8888  888     
                    888                     8888888b.  8888888b.   .d8888b.  8888888888 8888888888 .d8888b.                                           888                  
                    888                     888   Y88b 888   Y88b d88P  Y88b 888        888       d88P  Y88b                                     Y8b d88P                  
                    888                     888    888 888    888 888    888 888        888            .d88P                                       Y88P                    
                    88888b.  888  888       888   d88P 888   d88P 888    888 8888888    8888888       8888                                                                
                    888  88b 888  888       8888888P   8888888P   888    888 888        888             Y8b.                                                               
                    888  888 888  888       888        888 T88b   888    888 888        888       888    888                                                               
                    888 d88P Y88b 888       888        888  T88b  Y88b  d88P 888        888       Y88b  d88P                                                               
                    88888P     Y88888       888        888   T88b   Y8888P   888        888         Y8888P                                                                 
                                888                                                                                                                                      
                            Y8b d88P                                                                                                                                      
                              Y88P                                                                                                                                       
                """)
            while True:
                # Comprobar si existe una clave de cifrado
                if not os.path.exists("key.key"):
                    # Si no existe, solicitar una contraseña para crear la base de datos
                    password = getpass.getpass("Enter a password to encrypt the database: ").strip()
                    if not password:
                        clear()
                        print("The password cannot be blank.")
                        continue
                    key, salt = derive_key(password)
                    save_key(key, salt)
                    init_db()
                    clear()
                else:
                    # Si existe, solicitar la contraseña para acceder a la base de datos
                    password = getpass.getpass("Enter the password to decrypt the database: ").strip()
                    key, salt = load_key()
                    derived_key, _ = derive_key(password, salt)
                    if derived_key != key:
                        clear()
                        print(f"{Fore.RED}Incorrect{Style.RESET_ALL} password.")
                        continue
                    key = derived_key  # Aseguramos que key está asignado correctamente
                    clear()
                return key
            

        except KeyboardInterrupt:
            print(f"\nUser {Fore.RED}interruption{Style.RESET_ALL}.")
            exit(0)

# Uso del gestor de contraseñas
def main():
    key = initialize_password_manager()
    try:
        while True:
            print_menu()
            choice = input("Choose an option: ")

            if choice == '1':
                clear()
                service_name = input("Enter the name of the service: ").strip()
                if not service_name:
                    clear()
                    print("The service name cannot be blank.")
                    continue

                generate_secure = input(f"Do you want to generate a secure password? ({Fore.GREEN}yes{Style.RESET_ALL}/{Fore.RED}no{Style.RESET_ALL}): ").strip().lower()
                if generate_secure == "yes":
                    password = generate_secure_password()
                    store_password(service_name, password, key)
                elif generate_secure == "no":
                    password = input("Enter the password: ").strip()
                    store_password(service_name, password, key)
                if not password:
                    clear()
                    print("The password cannot be blank.")
                    continue
                elif not (generate_secure == "yes" or generate_secure == "no"):
                    clear()
                    print("Invalid option. Please enter 'yes' or 'no'.")
                    return
                else:
                    clear()
                    print(f"Password {Fore.GREEN}saved{Style.RESET_ALL} successfully")
                
            elif choice == '2':
                clear()
                service_name = select_service()
                if service_name:
                    decrypted_password = retrieve_password(service_name, key)
                    if decrypted_password:
                        clear()
                        print(f'The password for {service_name} is: {Fore.YELLOW}{decrypted_password}{Style.RESET_ALL} (Copied to clipboard)')
                        copy_with_timeout(decrypted_password)
                    else:
                        clear()
                        print("No password found for that service.")

            elif choice == '3':
                clear()
                service_name = select_service()
                if service_name:
                    print(f'The password for {service_name} is: {Fore.YELLOW}{decrypted_password}{Style.RESET_ALL}')
                    confirm = input(f"Are you sure you want to {Fore.GREEN}update{Style.RESET_ALL} the password for '{Fore.YELLOW}{service_name}{Style.RESET_ALL}'? ({Fore.GREEN}yes{Style.RESET_ALL}/{Fore.RED}no{Style.RESET_ALL}): ").strip().lower()
                if confirm == "yes":
                    new_password = input("Enter the new password: ").strip()
                    if not new_password:
                        clear()
                        print("The new password cannot be blank.")
                        continue
                    update_password(service_name, new_password, key)
                    clear()
                    print(f"Password {Fore.GREEN}updated{Style.RESET_ALL} successfully.")
                elif confirm == "no":
                    clear()
                    print("Updating canceled.")
                else:
                    clear()
                    print("Invalid option. Please enter 'yes' or 'no'.")
                    
            elif choice == '4':
                clear()
                service_name = select_service()
                if service_name:
                    confirm = input(f"Are you sure you want to {Fore.RED}delete{Style.RESET_ALL} the password for '{Fore.YELLOW}{service_name}{Style.RESET_ALL}'? ({Fore.GREEN}yes{Style.RESET_ALL}/{Fore.RED}no{Style.RESET_ALL}): ").strip().lower()
                if confirm == "yes":
                    delete_password(service_name)
                    clear()
                    print(f"Password {Fore.RED}deleted{Style.RESET_ALL} successfully.")
                elif confirm == "no":
                    clear()
                    print("Deletion canceled.")
                else:
                    clear()
                    print("Invalid option. Please enter 'yes' or 'no'.")


            elif choice == '5':
                clear()
                secure_password = generate_secure_password()
                print(f'Generated secure password: {Fore.GREEN}{secure_password}{Style.RESET_ALL} (copied to clipboard)')
                copy_with_timeout(secure_password)

            elif choice == '6':
                clear()
                print("Exiting the password manager.")
                print("\n by PR0FF3")
                break

            else:
                clear()
                print("Invalid option. Please choose an option from the menu.")
    except KeyboardInterrupt:
        clear()
        print(f"\nUser {Fore.RED}interruption{Style.RESET_ALL}. Exiting the password manager.")
        exit(0)
if __name__ == "__main__":
    main()