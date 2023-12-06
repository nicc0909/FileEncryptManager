from gc import disable
import time
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from ttkbootstrap import Style  # Importa la classe Style
from tkinter.simpledialog import askstring
from PIL import Image, ImageTk  # Importa Image e ImageTk da Pillow
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
import datetime  # Aggiungi l'import per il modulo 'time'
import threading
import bcrypt
import json
import atexit
import sys

# Percorso predefinito
default = os.path.dirname(os.path.abspath(__file__)) + "\\File"
temp =  os.path.dirname(os.path.abspath(__file__)) + "\\Temp"
password = os.path.dirname(os.path.abspath(__file__)) + "\\Settings\\password_data.json"
key = os.path.dirname(os.path.abspath(__file__)) + "\\Settings\\keyfile.json"

# Funzione per generare la chiave per la crittografia
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Funzione per criptare un file
def encrypt_file(file_path: str, password: str, output_path: str):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)
    
    try:
        with open(file_path, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        with open(output_path, 'wb') as encrypted_file:
            encrypted_file.write(salt + encrypted)  # Salva sale e dati criptati insieme

        # Mostra un messaggio di successo
        messagebox.showinfo("Successo", "Il file è stato criptato con successo.")
    except Exception as e:
        messagebox.showerror("Errore", f"Si è verificato un errore durante la criptazione: {str(e)}")

# Funzione per decriptare un file
def decrypt_file(encrypted_file_path: str, password: str, output_path: str):
    with open(encrypted_file_path, 'rb') as file:
        salt = file.read(16)  # I primi 16 byte sono il sale
        encrypted_data = file.read()

    key = generate_key(password, salt)
    fernet = Fernet(key)

    decrypted = fernet.decrypt(encrypted_data)

    with open(output_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

# Funzione per riempire la tabella con i file nella cartella specificata
def load_table():
    cartella = default  # Utilizza il percorso predefinito
    chack_create_key(key)
    # Cancella tutti gli elementi dalla tabella
    for row in tree.get_children():
        tree.delete(row)
    
    # Ottieni una lista dei file nella cartella
    file_list = os.listdir(cartella)
    
    # Aggiungi i file alla tabella con informazioni aggiuntive
    for file in file_list:
        try:
            # Decripta il nome del file
            decrypted_file_name = decrypt_name(file, load_key(key))
        except Exception as e:
            print(f"Errore durante la decriptazione del file {file}: {e}")
            decrypted_file_name = file  # Usa il nome criptato se la decriptazione fallisce

        file_path = os.path.join(cartella, file)
        file_size = os.path.getsize(file_path)
        file_tipo = "Cartella" if os.path.isdir(file_path) else "File"
        file_ultima_modifica = datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
        tree.insert("", "end", values=(decrypted_file_name, file_size, file_tipo, file_ultima_modifica, file_path))

# Funzione per scaricare il file selezionato (decriptato)
def download():
    selected_item = tree.selection()
    item = tree.item(selected_item[0])
    file_path = item['values'][4]
    file_tipo = item['values'][2]
    if selected_item and file_tipo == 'File':
        if file_path:
            password = password_entry.get()  # Ottieni la password dall'Entry
            file_name = os.path.basename(file_path)
            try:
                # Decripta il nome del file
                file_name = decrypt_name(file_name, load_key(key))
            except Exception as e:
                print(f"Errore durante la decriptazione del file {file}: {e}")
                file_name = file_name  # Usa il nome criptato se la decriptazione fallisce
            percorso_destinazione_temp = os.path.join(temp, file_name)

            # Decripta il file selezionato
            try:
                decrypt_file(file_path, password, percorso_destinazione_temp)

                # Mostra una finestra di dialogo per selezionare la destinazione del download
                percorso_destinazione = filedialog.asksaveasfilename(defaultextension="*", initialfile=file_name)
                if percorso_destinazione:
                    # Copia il file decriptato nella destinazione selezionata
                    shutil.copy(percorso_destinazione_temp, percorso_destinazione)

                    # Mostra un messaggio di successo
                    messagebox.showinfo("Successo", "Il file è stato scaricato con successo.")
                    os.remove(percorso_destinazione_temp)  # Rimuovi il file temporaneo
            except Exception as e:
                messagebox.showerror("Error", f"Si è verificato un errore, la passoword inserita non è valida. {str(e)}")

# Funzione per caricare un file nella cartella predefinita e crittografarlo
def upload():
    password = password_entry.get()  # Ottieni la password dall'Entry
    file_da_caricare = filedialog.askopenfilename()
    print(file_da_caricare)
    if file_da_caricare:
        # Cripta il nome del file
        nome_file_criptato_binario = encrypt_name(os.path.basename(file_da_caricare), load_key(key))

        # Converti il nome criptato in una stringa sicura per il filesystem
        nome_file_criptato = base64.urlsafe_b64encode(nome_file_criptato_binario).decode()

        # Costruisci il percorso di destinazione
        percorso_destinazione = os.path.join(default, nome_file_criptato)
        os.makedirs(os.path.dirname(percorso_destinazione), exist_ok=True)  # Crea la cartella se non esiste

        # Copia il file nella destinazione
        shutil.copy(file_da_caricare, percorso_destinazione)

        # Crittografare il file appena copiato
        encrypt_file(percorso_destinazione, password, percorso_destinazione)

        load_table()


def delete():
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item[0])
        file_path = item['values'][4]
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)  # Rimuovi la directory e il suo contenuto
        else:
            os.remove(file_path)  # Rimuovi il file
        load_table()

def view_file(event):
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item[0])
        file_tipo = item['values'][2]
        file_path = item['values'][4]

        if file_tipo == 'File':
            password = password_entry.get()  # Ottieni la password dall'Entry
            file_name = os.path.basename(file_path)
            try:
                # Decripta il nome del file
                file_name = decrypt_name(file_name, load_key(key))
            except Exception as e:
                print(f"Errore durante la decriptazione del file {file}: {e}")
                file_name = file_name  # Usa il nome criptato se la decriptazione fallisce
            percorso_destinazione_temp = os.path.join(temp, file_name)

            # Decripta il file selezionato
            try:
                decrypt_file(file_path, password, percorso_destinazione_temp)

                # Apri il file decriptato con l'applicazione predefinita
                os.startfile(percorso_destinazione_temp)

                timer = threading.Timer(600, delate_file, [percorso_destinazione_temp, 600])
                timer.start()
            except Exception as e:
                messagebox.showerror("Errore", f"Si è verificato un errore, la password inserita non è valida. {str(e)}")
        elif file_tipo == 'Cartella':
            # Gestione delle cartelle come prima
            global default
            default = file_path
            load_table()

def delate_file(file_path, intervallo):
    try:
        time.sleep(intervallo)  # Attende l'intervallo specificato (in secondi)
        os.remove(file_path)  # Rimuove il file
        print(f"File eliminato: {file_path}")  # Stampa di conferma per il debug
        sys.exit()
    except Exception as e:
        messagebox.showerror("Errore", f"Si è verificato un errore nella eliminazione del file. {str(e)}")

def back():
    global default
    if default != os.path.dirname(os.path.abspath(__file__)) + "\\File":
        default = os.path.dirname(default)
        load_table()

def create_directory():
    global default

    try:
        # Cripta il nome della cartella e lo codifica in Base64
        encrypted_folder_name = encrypt_name("New Folder", load_key(key))
        safe_folder_name = base64.urlsafe_b64encode(encrypted_folder_name).decode()
        
        # Crea un percorso valido per la nuova cartella
        new_folder_path = os.path.join(default, safe_folder_name)
        os.makedirs(new_folder_path, exist_ok=True)
        
    except Exception as e:
        messagebox.showerror("Errore", f"Si è verificato un errore nella creazione della cartella: {str(e)}")
    
    load_table()

def rename_item():
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item[0])
        file_path = item['values'][4]
        file_tipo = item['values'][2]

        # Estrai il nome del file e l'estensione
        file_name = os.path.basename(file_path)
        file_name = decrypt_name(file_name, load_key(key))

        # Chiedi all'utente il nuovo nome, senza estensione
        new_name = askstring("Rinomina", "Inserisci il nuovo nome (senza estensione):")
        if new_name:
            # Converti il nome criptato in una stringa sicura per il filesystem
            nome_completo = new_name + os.path.splitext(file_name)[1]
            nome_file_criptato_binario = encrypt_name(nome_completo, load_key(key))
            nome_file_criptato = base64.urlsafe_b64encode(nome_file_criptato_binario).decode()
            new_path = os.path.join(os.path.dirname(file_path), nome_file_criptato)
            try:
                os.rename(file_path, new_path)
                load_table()
                messagebox.showinfo("Successo", f"{file_tipo} rinominato con successo.")
            except Exception as e:
                messagebox.showerror("Errore", f"Si è verificato un errore durante la rinomina: {str(e)}")
    else:
        messagebox.showwarning("Attenzione", "Seleziona un file o una cartella.")

def check_password():
    password_inserita = simpledialog.askstring("Password", "Inserisci la password per aprire il file manager:", show='*')
    if check_hash_password(password, password_inserita):  # Sostituisci con la password corretta
        root.deiconify()
    else:
        tk.messagebox.showerror("Errore", "Password errata.")
        root.quit()

def save_password_hash(file_path, password):
    # Hash della password
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password.encode(), salt)

    # Salvataggio dell'hash in un file JSON
    with open(file_path, 'w') as file:
        json.dump({'password_hash': password_hash.decode()}, file)

def check_hash_password(file_path, password):
    # Lettura dell'hash dal file JSON
    with open(file_path, 'r') as file:
        data = json.load(file)
        password_hash = data['password_hash'].encode()

    # Verifica della password
    return bcrypt.checkpw(password.encode(), password_hash)

def reset_password():
    password_inserita = simpledialog.askstring("Password", "Inserisci la nuova password per aprire il file manager:", show='*')
    save_password_hash(password, password_inserita)

def generate_aes_key(length=32):
    return os.urandom(length)

def chack_create_key(file_path: str):
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        load_key(file_path)
    else:
        # Salva una nuova chiave se non esiste
        save_key(generate_aes_key(), file_path)

def save_key(key: bytes, file_path: str):
    with open(file_path, 'w') as file:
        # Codifica la chiave in base64 per la serializzazione JSON
        encoded_key = base64.b64encode(key).decode('utf-8')
        json.dump({'key': encoded_key}, file)

def load_key(file_path: str) -> bytes:
    with open(file_path, 'r') as file:
        data = json.load(file)
        # Decodifica la chiave dal formato base64
        return base64.b64decode(data['key'])

def encrypt_name(name: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(name.encode()) + encryptor.finalize()
    return encrypted_data

def decrypt_name(encrypted_data: str, key: bytes) -> str:
    # Decodifica i dati criptati (che sono in Base64) in binario
    encrypted_data_bytes = base64.urlsafe_b64decode(encrypted_data)

    # Estrae il nonce (IV) dai dati criptati
    iv = encrypted_data_bytes[:16]  # Assumi che l'IV sia lungo 16 byte
    encrypted_content = encrypted_data_bytes[16:]

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

    return decrypted_data.decode()


def open_home_menu(event):
    # Crea un menu a tendina quando si preme su "Home"
    home_menu = tk.Menu(root, tearoff=0)
    home_menu.add_command(label="Reset Password", command=reset_password)
    home_menu.add_command(label="Clear Temp", command=clear_temp)
    home_menu.add_command(label="Exit", command=root.quit)
    
    # Calcola le coordinate x e y per il menu a tendina
    x = event.widget.winfo_rootx()
    y = event.widget.winfo_rooty() + event.widget.winfo_height()
    
    # Mostra il menu a tendina
    home_menu.post(x, y)

def clear_temp():
    try:
        for filename in os.listdir(temp):
            file_path = os.path.join(temp, filename)
            os.remove(file_path)
        
        messagebox.showinfo("Successo", "i file temporanei sono stati eliminati.")
    except Exception as e:
        print(f"Si è verificato un errore durante l'eliminazione dei file: {e}")

def download_threaded():
    # Creare e avviare un nuovo thread per eseguire la funzione download
    thread = threading.Thread(target=download)
    thread.start()

def upload_threaded():
    # Creare e avviare un nuovo thread per eseguire la funzione download
    thread = threading.Thread(target=upload)
    thread.start()


# Crea una finestra con ttkbootstrap Style
root = tk.Tk()
root.withdraw()  # Nasconde la finestra principale
style = Style(theme="darkly")  # Puoi scegliere uno dei temi disponibili
root.iconbitmap(default=os.path.dirname(os.path.abspath(__file__))  + '\\Image\\app.ico') 
# Personalizza il titolo e l'icona della finestra
root.title("File Manager")
check_password()
# Imposta le dimensioni della finestra
larghezza_finestra = 900
altezza_finestra = 600

# Ottieni le dimensioni dello schermo
larghezza_schermo = root.winfo_screenwidth()
altezza_schermo = root.winfo_screenheight()

# Calcola le coordinate x e y per centrare la finestra
x = (larghezza_schermo - larghezza_finestra) // 2
y = (altezza_schermo - altezza_finestra) // 2

# Imposta la posizione della finestra al centro dello schermo
root.geometry(f"{larghezza_finestra}x{altezza_finestra}+{x}+{y}")

menu_bar_frame = tk.Frame(root, bg='blue', height=20)
menu_bar_frame.pack(side=tk.TOP, fill=tk.X)
menu_bar_frame.pack_propagate(False)
# Creazione di un pulsante "Home" con un menu a tendina
home_button = tk.Button(menu_bar_frame, text="Home")
home_button.pack(side=tk.LEFT)
home_button.bind("<Button-1>", open_home_menu)  # Lega la funzione al clic sinistro
bar_button = tk.Button(menu_bar_frame, state=tk.DISABLED)
bar_button.pack(fill=tk.BOTH, expand=True)


# Creazione del frame per i pulsanti e l'input per la password
frame_pulsanti = ttk.Frame(root)
frame_pulsanti.pack(side="top", padx=10, pady=10)  # Posiziona il frame sopra la tabella

img = Image.open(os.path.dirname(os.path.abspath(__file__))  + '\\Image\\back.png')
image = ImageTk.PhotoImage(img)
# Crea un bottone con l'immagine
btn_precedente = ttk.Button(root, image=image, command=back)
btn_precedente.pack(side="left", padx=5)

# Pulsante per eliminare il file selezionato
btn_delete = ttk.Button(frame_pulsanti, text="Crea Cartella", command=create_directory)
btn_delete.pack(side="left", padx=5)

# Campo per inserire la password
password_label = ttk.Label(frame_pulsanti, text="Inserisci la password:")
password_label.pack(side="left", padx=5)
password_entry = ttk.Entry(frame_pulsanti, show="*")  # Mostra * al posto dei caratteri
password_entry.pack(side="left", padx=5)

# Pulsante per scaricare il file selezionato
btn_download = ttk.Button(frame_pulsanti, text="Download", command=download_threaded)
btn_download.pack(side="left", padx=5)

# Pulsante per caricare un file nella cartella predefinita
btn_carica = ttk.Button(frame_pulsanti, text="Upload", command=upload_threaded)
btn_carica.pack(side="left", padx=5)

# Aggiungi un pulsante per rinominare le cartelle
btn_rename = ttk.Button(frame_pulsanti, text="Rinomina", command=rename_item)
btn_rename.pack(side="left", padx=5)

# Pulsante per eliminare il file selezionato
btn_delete = ttk.Button(frame_pulsanti, text="Elimina", command=delete)
btn_delete.pack(side="left", padx=5)

style.configure("Treeview", font=('TLabel', 10))  # Cambia 'Helvetica' e 12 con il tuo font e dimensione desiderati
# Creazione della tabella con colonne aggiuntive
tree = ttk.Treeview(root, style="Treeview", columns=("File", "Dimensione", "Tipo", "Ultima Modifica"), show="headings")
tree.bind("<Double-1>", view_file)
tree.heading("File", text="File")
tree.heading("Dimensione", text="Dimensione")
tree.heading("Tipo", text="Tipo")
tree.heading("Ultima Modifica", text="Ultima Modifica")  # Aggiungi la colonna "Ultima Modifica"
tree.pack()


# Imposta l'opzione fill per espandere la tabella in entrambe le direzioni (orizzontale e verticale)
tree.pack(padx=5,pady=5,fill="both", expand=True)

load_table()

# Esegui la finestra principale
root.mainloop()