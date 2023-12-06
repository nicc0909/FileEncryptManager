from gc import disable
import time
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from ttkbootstrap import Style  # Import the Style class
from tkinter.simpledialog import askstring
from PIL import Image, ImageTk  # Import Image and ImageTk from Pillow
from tkinter import simpledialog
import tkinter.messagebox as messagebox
import os
import shutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import datetime  # Add import for 'datetime' module
import threading
import bcrypt
import json
import atexit
import sys

# Default path
default = os.path.dirname(os.path.abspath(__file__)) + "\\File"
temp = os.path.dirname(os.path.abspath(__file__)) + "\\Temp"
password = os.path.dirname(os.path.abspath(__file__)) + "\\Settings\\password_data.json"
key = os.path.dirname(os.path.abspath(__file__)) + "\\Settings\\keyfile.json"

# Function to generate the encryption key
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Function to encrypt a file
def encrypt_file(file_path: str, password: str, output_path: str):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)
    
    try:
        with open(file_path, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        with open(output_path, 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted)  # Save salt and encrypted data together

        # Display a success message
        messagebox.showinfo("Success", "The file has been successfully encrypted.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")

# Function to decrypt a file
def decrypt_file(encrypted_file_path: str, password: str, output_path: str):
    with open(encrypted_file_path, 'rb') as file:
        salt = file.read(16)  # First 16 bytes are the salt
        encrypted_data = file.read()

    key = generate_key(password, salt)
    fernet = Fernet(key)

    decrypted = fernet.decrypt(encrypted_data)

    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

# Function to populate the table with files from the specified folder
def load_table():
    folder = default  # Use the default path
    chack_create_key(key)
    # Clear all items from the table
    for row in tree.get_children():
        tree.delete(row)
    
    # Get a list of files in the folder
    file_list = os.listdir(folder)
    
    # Add files to the table with additional information
    for file in file_list:
        try:
            # Decrypt the file name
            decrypted_file_name = decrypt_name(file, load_key(key))
        except Exception as e:
            print(f"Error during the decryption of the file {file}: {e}")
            decrypted_file_name = file  # Use the encrypted name if decryption fails

        file_path = os.path.join(folder, file)
        file_size = os.path.getsize(file_path)
        file_type = "Folder" if os.path.isdir(file_path) else "File"
        file_last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
        tree.insert("", "end", values=(decrypted_file_name, file_size, file_type, file_last_modified, file_path))

# Function to download the selected (decrypted) file
def download():
    selected_item = tree.selection()
    item = tree.item(selected_item[0])
    file_path = item['values'][4]
    file_type = item['values'][2]
    if selected_item and file_type == 'File':
        if file_path:
            password = password_entry.get()  # Get the password from the Entry
            file_name = os.path.basename(file_path)
            try:
                # Decrypt the file name
                file_name = decrypt_name(file_name, load_key(key))
            except Exception as e:
                print(f"Error during the decryption of the file {file}: {e}")
                file_name = file_name  # Use the encrypted name if decryption fails
            temp_destination_path = os.path.join(temp, file_name)

            # Decrypt the selected file
            try:
                decrypt_file(file_path, password, temp_destination_path)

                # Display a dialog window to select the download destination
                destination_path = filedialog.asksaveasfilename(defaultextension="*", initialfile=file_name)
                if destination_path:
                    # Copy the decrypted file to the selected destination
                    shutil.copy(temp_destination_path, destination_path)

                    # Display a success message
                    messagebox.showinfo("Success", "The file has been successfully downloaded.")
                    os.remove(temp_destination_path)  # Remove the temporary file
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred, the entered password is not valid. {str(e)}")

# Function to upload a file to the default folder and encrypt it
def upload():
    password = password_entry.get()  # Get the password from the Entry
    file_to_upload = filedialog.askopenfilename()
    print(file_to_upload)
    if file_to_upload:
        # Encrypt the file name
        encrypted_file_name_binary = encrypt_name(os.path.basename(file_to_upload), load_key(key))

        # Convert the encrypted name to a filesystem-safe string
        encrypted_file_name = base64.urlsafe_b64encode(encrypted_file_name_binary).decode()

        # Build the destination path
        destination_path = os.path.join(default, encrypted_file_name)
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)  # Create the folder if it doesn't exist

        # Copy the file to the destination
        shutil.copy(file_to_upload, destination_path)

        # Encrypt the newly copied file
        encrypt_file(destination_path, password, destination_path)

        load_table()


def delete():
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item[0])
        file_path = item['values'][4]
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)  # Remove the directory and its contents
        else:
            os.remove(file_path)  # Remove the file
        load_table()

def view_file(event):
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item[0])
        file_type = item['values'][2]
        file_path = item['values'][4]

        if file_type == 'File':
            password = password_entry.get()  # Get the password from the Entry
            file_name = os.path.basename(file_path)
            try:
                # Decrypt the file name
                file_name = decrypt_name(file_name, load_key(key))
            except Exception as e:
                print(f"Error during the decryption of the file {file}: {e}")
                file_name = file_name  # Use the encrypted name if decryption fails
            temp_destination_path = os.path.join(temp, file_name)

            # Decrypt the selected file
            try:
                decrypt_file(file_path, password, temp_destination_path)

                # Open the decrypted file with the default application
                os.startfile(temp_destination_path)

                timer = threading.Timer(600, delate_file, [temp_destination_path, 600])
                timer.start()
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred, the entered password is not valid. {str(e)}")
        elif file_type == 'Folder':
            # Handling folders as before
            global default
            default = file_path
            load_table()

def delate_file(file_path, interval):
    try:
        time.sleep(interval)  # Wait for the specified interval (in seconds)
        os.remove(file_path)  # Remove the file
        print(f"File deleted: {file_path}")  # Debug confirmation print
        sys.exit()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred in the file deletion. {str(e)}")


def back():
    global default
    if default != os.path.dirname(os.path.abspath(__file__)) + "\\File":
        default = os.path.dirname(default)
        load_table()

def create_directory():
    global default

    try:
        # Encrypt the folder name and encode it in Base64
        encrypted_folder_name = encrypt_name("New Folder", load_key(key))
        safe_folder_name = base64.urlsafe_b64encode(encrypted_folder_name).decode()
        
        # Create a valid path for the new folder
        new_folder_path = os.path.join(default, safe_folder_name)
        os.makedirs(new_folder_path, exist_ok=True)
        
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while creating the folder: {str(e)}")
    
    load_table()

def rename_item():
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item[0])
        file_path = item['values'][4]
        file_type = item['values'][2]

        # Extract the file name and extension
        file_name = os.path.basename(file_path)
        file_name = decrypt_name(file_name, load_key(key))

        # Ask the user for the new name, without extension
        new_name = askstring("Rename", "Enter the new name (without extension):")
        if new_name:
            # Convert the encrypted name into a filesystem-safe string
            full_name = new_name + os.path.splitext(file_name)[1]
            encrypted_file_name_binary = encrypt_name(full_name, load_key(key))
            encrypted_file_name = base64.urlsafe_b64encode(encrypted_file_name_binary).decode()
            new_path = os.path.join(os.path.dirname(file_path), encrypted_file_name)
            try:
                os.rename(file_path, new_path)
                load_table()
                messagebox.showinfo("Success", f"{file_type} successfully renamed.")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred during the renaming: {str(e)}")
    else:
        messagebox.showwarning("Attention", "Select a file or a folder.")

def check_password():
    entered_password = simpledialog.askstring("Password", "Enter the password to open the file manager:", show='*')
    if check_hash_password(password, entered_password):  # Replace with the correct password
        root.deiconify()
    else:
        tk.messagebox.showerror("Error", "Incorrect password.")
        root.quit()

def save_password_hash(file_path, password):
    # Hash the password
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode(), salt)

    # Save the hash in a JSON file
    with open(file_path, 'w') as file:
        json.dump({'password_hash': password_hash.decode()}, file)

def check_hash_password(file_path, password):
    # Read the hash from the JSON file
    with open(file_path, 'r') as file:
        data = json.load(file)
        password_hash = data['password_hash'].encode()

    # Verify the password
    return bcrypt.checkpw(password.encode(), password_hash)

def reset_password():
    entered_password = simpledialog.askstring("Password", "Enter the new password for the file manager:", show='*')
    save_password_hash(password, entered_password)

def generate_aes_key(length=32):
    return os.urandom(length)

def chack_create_key(file_path: str):
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        load_key(file_path)
    else:
        # Save a new key if it does not exist
        save_key(generate_aes_key(), file_path)

def save_key(key: bytes, file_path: str):
    with open(file_path, 'w') as file:
        # Encode the key in base64 for JSON serialization
        encoded_key = base64.b64encode(key).decode('utf-8')
        json.dump({'key': encoded_key}, file)

def load_key(file_path: str) -> bytes:
    with open(file_path, 'r') as file:
        data = json.load(file)
        # Decode the key from base64 format
        return base64.b64decode(data['key'])

def encrypt_name(name: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(name.encode()) + encryptor.finalize()
    return encrypted_data

def decrypt_name(encrypted_data: str, key: bytes) -> str:
    # Decode the encrypted data (which is in Base64) to binary
    encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data)

    # Extract the nonce (IV) from the encrypted data
    iv = encrypted_data_bytes[:16]  # Assume the IV is 16 bytes long
    encrypted_content = encrypted_data_bytes[16:]

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

    return decrypted_data.decode()


def open_home_menu(event):
    # Create a dropdown menu when clicking on "Home"
    home_menu = tk.Menu(root, tearoff=0)
    home_menu.add_command(label="Reset Password", command=reset_password)
    home_menu.add_command(label="Clear Temp", command=clear_temp)
    home_menu.add_command(label="Exit", command=root.quit)
    
    # Calculate the x and y coordinates for the dropdown menu
    x = event.widget.winfo_rootx()
    y = event.widget.winfo_rooty() + event.widget.winfo_height()
    
    # Display the dropdown menu
    home_menu.post(x, y)

def clear_temp():
    try:
        for filename in os.listdir(temp):
            file_path = os.path.join(temp, filename)
            os.remove(file_path)
        
        messagebox.showinfo("Success", "Temporary files have been deleted.")
    except Exception as e:
        print(f"An error occurred while deleting files: {e}")

def download_threaded():
    # Create and start a new thread to execute the download function
    thread = threading.Thread(target=download)
    thread.start()

def upload_threaded():
    # Create and start a new thread to execute the upload function
    thread = threading.Thread(target=upload)
    thread.start()


# Create a window with ttkbootstrap Style
root = tk.Tk()
root.withdraw()  # Hide the main window
style = Style(theme="darkly")  # You can choose one of the available themes
root.iconbitmap(default=os.path.dirname(os.path.abspath(__file__))  + '\\Image\\app.ico') 
# Customize the title and icon of the window
root.title("File Manager")
check_password()
# Set the window dimensions
window_width = 900
window_height = 600

# Get the screen dimensions
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate the x and y coordinates to center the window
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2

# Set the window position to the center of the screen
root.geometry(f"{window_width}x{window_height}+{x}+{y}")

menu_bar_frame = tk.Frame(root, bg='blue', height=20)
menu_bar_frame.pack(side=tk.TOP, fill=tk.X)
menu_bar_frame.pack_propagate(False)
# Create a "Home" button with a dropdown menu
home_button = tk.Button(menu_bar_frame, text="Home")
home_button.pack(side=tk.LEFT)
home_button.bind("<Button-1>", open_home_menu)  # Bind the function to left click
bar_button = tk.Button(menu_bar_frame, state=tk.DISABLED)
bar_button.pack(fill=tk.BOTH, expand=True)


# Create the frame for buttons and password input
buttons_frame = ttk.Frame(root)
buttons_frame.pack(side="top", padx=10, pady=10)  # Position the frame above the table

img = Image.open(os.path.dirname(os.path.abspath(__file__))  + '\\Image\\back.png')
image = ImageTk.PhotoImage(img)
# Create a button with the image
btn_back = ttk.Button(root, image=image, command=back)
btn_back.pack(side="left", padx=5)

# Button to create a new folder
btn_create_folder = ttk.Button(buttons_frame, text="Create Folder", command=create_directory)
btn_create_folder.pack(side="left", padx=5)

# Field to enter the password
password_label = ttk.Label(buttons_frame, text="Enter Password:")
password_label.pack(side="left", padx=5)
password_entry = ttk.Entry(buttons_frame, show="*")  # Show * instead of characters
password_entry.pack(side="left", padx=5)

# Button to download the selected file
btn_download = ttk.Button(buttons_frame, text="Download", command=download_threaded)
btn_download.pack(side="left", padx=5)

# Button to upload a file to the default folder
btn_upload = ttk.Button(buttons_frame, text="Upload", command=upload_threaded)
btn_upload.pack(side="left", padx=5)

# Add a button to rename folders
btn_rename = ttk.Button(buttons_frame, text="Rename", command=rename_item)
btn_rename.pack(side="left", padx=5)

# Button to delete the selected file
btn_delete = ttk.Button(buttons_frame, text="Delete", command=delete)
btn_delete.pack(side="left", padx=5)

style.configure("Treeview", font=('TLabel', 10))  # Change 'Helvetica' and 12 to your desired font and size
# Creation of the table with additional columns
tree = ttk.Treeview(root, style="Treeview", columns=("File", "Size", "Type", "Last Modified"), show="headings")
tree.bind("<Double-1>", view_file)
tree.heading("File", text="File")
tree.heading("Size", text="Size")
tree.heading("Type", text="Type")
tree.heading("Last Modified", text="Last Modified")  # Add the "Last Modified" column
tree.pack()

# Set the fill option to expand the table in both directions (horizontal and vertical)
tree.pack(padx=5, pady=5, fill="both", expand=True)

load_table()

# Execute the main window
root.mainloop()
