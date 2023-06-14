import tkinter as tk
from tkinter import messagebox, filedialog, Scrollbar, RIGHT, Y, X, NONE, END, TOP, Text
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
import moviepy.editor as mp

def select_folder():
    # Meminta pengguna untuk memilih folder
    foldername = filedialog.askdirectory()
    if foldername:
        entry_foldername.delete(0, "end")
        entry_foldername.insert(0, foldername)

def show_homepage():
    homepage_frame.pack()
    generate_key_page_frame.pack_forget()
    encrypt_page_frame.pack_forget()
    decrypt_page_frame.pack_forget()

def show_encrypt_page():
    encrypt_page_frame.pack()
    homepage_frame.pack_forget()

def show_decrypt_page():
    decrypt_page_frame.pack()
    homepage_frame.pack_forget()

def show_key_page():
    generate_key_page_frame.pack()
    homepage_frame.pack_forget()

def generate_key_pair():
    # Mendapatkan nama folder dari entri teks
    foldername = entry_foldername.get()
    if not foldername:
        messagebox.showerror("Error", "Nama folder tidak valid.")
        return
    
    # Meminta input dari pengguna untuk menyimpan kunci dengan nama tertentu
    filename = entry_filename.get()
    if not filename:
        messagebox.showerror("Error", "Nama file kunci tidak valid.")
        return
    
    # Membuat folder jika belum ada
    if not os.path.exists(foldername):
        os.makedirs(foldername)
    
    # Generate pasangan kunci RSA
    key = RSA.generate(2048)
    
    # Simpan kunci privat ke file
    private_key = key.export_key()
    private_filename = os.path.join(foldername, f"{filename}_private.pem")
    with open(private_filename, "wb") as private_file:
        private_file.write(private_key)
    
    # Simpan kunci publik ke file
    public_key = key.publickey().export_key()
    public_filename = os.path.join(foldername, f"{filename}_public.pem")
    with open(public_filename, "wb") as public_file:
        public_file.write(public_key)
    
    messagebox.showinfo("Info", "Pasangan kunci RSA berhasil dibuat dan disimpan.")

def encrypt_text():
    # Meminta input teks untuk dienkripsi
    plaintext = entry_plaintext.get("1.0", "end-1c")
    if not plaintext:
        messagebox.showerror("Error", "Teks plaintext tidak boleh kosong.")
        return
    
    # Meminta input file kunci publik
    key_file = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    if not key_file:
        messagebox.showerror("Error", "File kunci publik tidak valid.")
        return
    
    # Membaca kunci publik
    with open(key_file, "rb") as file:
        key = RSA.import_key(file.read())
    
    # Membuat objek cipher dengan menggunakan kunci publik
    cipher = PKCS1_OAEP.new(key)
    
    # Melakukan enkripsi teks
    ciphertext = cipher.encrypt(plaintext.encode())
    
    # Menampilkan hasil enkripsi
    entry_ciphertext.delete("1.0", "end")
    entry_ciphertext.insert("1.0", ciphertext.hex())

def embed_ciphertext():
    # Meminta input file gambar
    image_file = filedialog.askopenfilename(filetypes=[("Image Files", "*.png")])
    if not image_file:
        messagebox.showerror("Error", "File gambar tidak valid.")
        return
    
    # Meminta input teks ciphertext
    ciphertext_hex = entry_ciphertext.get("1.0", "end-1c")
    if not ciphertext_hex:
        messagebox.showerror("Error", "Teks ciphertext tidak boleh kosong.")
        return
    
    # Membaca data gambar
    with open(image_file, "rb") as file:
        image_data = file.read()
    
    # Menyisipkan ciphertext ke dalam data gambar menggunakan steganografi EOF
    image_with_ciphertext = image_data + b"EOF" + bytes.fromhex(ciphertext_hex)
    
    # Meminta pengguna untuk memilih folder untuk menyimpan gambar hasil
    foldername = filedialog.askdirectory()
    if not foldername:
        messagebox.showerror("Error", "Nama folder tidak valid.")
        return
    
    # Mendapatkan nama file gambar
    image_filename = os.path.basename(image_file)
    
    # Menyimpan gambar dengan ciphertext
    image_with_ciphertext_filename = os.path.join(foldername, f"{image_filename}_with_ciphertext.png")
    with open(image_with_ciphertext_filename, "wb") as file:
        file.write(image_with_ciphertext)
    
    messagebox.showinfo("Info", "Ciphertext berhasil disisipkan ke dalam file gambar.")

def extract_ciphertext():
    # Meminta input file gambar yang berisi ciphertext
    image_file = filedialog.askopenfilename(filetypes=[("Image Files", "*.png")])
    if not image_file:
        messagebox.showerror("Error", "File gambar tidak valid.")
        return
    
    # Membaca data gambar
    with open(image_file, "rb") as file:
        image_data = file.read()
    
    # Mencari posisi EOF
    eof_position = image_data.find(b"EOF")
    if eof_position == -1:
        messagebox.showerror("Error", "EOF tidak ditemukan pada gambar.")
        return
    
    # Memisahkan ciphertext dari data gambar
    ciphertext = image_data[eof_position+3:]
    
    # Menampilkan ciphertext
    entry_extracted_ciphertext.delete("1.0", "end")
    entry_extracted_ciphertext.insert("1.0", ciphertext.hex())

def decrypt_ciphertext():
    # Meminta input ciphertext untuk didekripsi
    ciphertext_hex = entry_extracted_ciphertext.get("1.0", "end-1c")
    if not ciphertext_hex:
        messagebox.showerror("Error", "Teks ciphertext tidak boleh kosong.")
        return
    
    # Meminta input file kunci privat
    key_file = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    if not key_file:
        messagebox.showerror("Error", "File kunci privat tidak valid.")
        return
    
    # Membaca kunci privat
    with open(key_file, "rb") as file:
        key = RSA.import_key(file.read())
    
    # Membuat objek cipher dengan menggunakan kunci privat
    cipher = PKCS1_OAEP.new(key)
    
    # Mendekripsi ciphertext
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = cipher.decrypt(ciphertext).decode()
    
    # Menampilkan hasil dekripsi
    entry_decrypted_text.delete("1.0", "end")
    entry_decrypted_text.insert("1.0", plaintext)

def select_image_file():
    # Meminta pengguna untuk memilih file gambar
    image_file = filedialog.askopenfilename(filetypes=[("Image Files", "*.png")])
    if image_file:
        entry_image_file.delete(0, "end")
        entry_image_file.insert(0, image_file)

def select_video_file():
    # Meminta pengguna untuk memilih file video
    video_file = filedialog.askopenfilename(filetypes=[("Video Files", "*.mp4")])
    if video_file:
        entry_video_file.delete(0, "end")
        entry_video_file.insert(0, video_file)

def select_embeded_video_file():
    # Meminta pengguna untuk memilih file video
    video_file = filedialog.askopenfilename(filetypes=[("Video Files", "*.mp4")])
    if video_file:
        entry_embeded_video_file.delete(0, "end")
        entry_embeded_video_file.insert(0, video_file)

def embed_image_in_video():
    # Meminta input file gambar
    image_path = entry_image_file.get()
    if not image_path:
        messagebox.showerror("Error", "File gambar tidak valid.")
        return
    
    # Meminta input file video
    video_path = entry_video_file.get()
    if not video_path:
        messagebox.showerror("Error", "File video tidak valid.")
        return
    with open(video_path, "rb") as video_file:
        video_data = video_file.read()
    with open(image_path, "rb") as image_file:
        image_data = image_file.read()

    video_with_image_data = video_data + b"EOFV" + image_data

    video_extension = os.path.splitext(video_path)[1]
    video_output_path = os.path.splitext(video_path)[0] + "_encrypted" + video_extension
    
    # Write the video with encrypted image data to a new file
    with open(video_output_path, "wb") as video_output_file:
        video_output_file.write(video_with_image_data)
    
    messagebox.showinfo("Info", "Gambar berhasil disisipkan ke dalam video.")

def extract_image_in_video():
    video_path = entry_embeded_video_file.get()
    if not video_path:
        messagebox.showerror("Error", "File video tidak valid.")
        return
    with open(video_path, "rb") as video_file:
        video_data = video_file.read()
    
    image_pos = video_data.find(b"EOFV")
    if image_pos == -1:
        messagebox.showerror("Error", "EOF tidak ditemukan pada video.")
        return
    else :
        image_data = video_data[image_pos+4:]
    
    image_extension = ".png"
    image_output_path = os.path.splitext(video_path)[0] + "_extracted" + image_extension
    
    # Write the video with encrypted image data to a new file
    with open(image_output_path, "wb") as image_output_file:
        image_output_file.write(image_data)
    
    messagebox.showinfo("Info", "Gambar berhasil diekstrak ke "+image_output_path)

# Membuat GUI menggunakan Tkinter
window = tk.Tk()

frame = tk.Frame(window)
frame.pack()

frame.grid_rowconfigure(0, weight=1)
frame.grid_columnconfigure(0, weight=1)

window.title("RSA Encryption & EOF Steganograpgy")
window.geometry("800x500")

homepage_frame = tk.Frame(window)
encrypt_page_frame = tk.Frame(window)
decrypt_page_frame = tk.Frame(window)
generate_key_page_frame = tk.Frame(window)

label_welcome = tk.Label(homepage_frame, text="SELAMAT DATANG ADMIN", font=("Arial", 17))
label_welcome.pack()
label_welcome = tk.Label(homepage_frame, text=" ", font=("Arial", 17))
label_welcome.pack()

button_next = tk.Button(homepage_frame, text="Buat Kunci", command=show_key_page)
button_next.pack()

button_next = tk.Button(homepage_frame, text="Enkripsi", command=show_encrypt_page)
button_next.pack()

button_next = tk.Button(homepage_frame, text="Dekripsi", command=show_decrypt_page)
button_next.pack()

##########################################################################################################################################

label_welcome = tk.Label(generate_key_page_frame, text="GENERATE YOUR KEY", font=("Arial", 14))
label_welcome.pack()

label_welcome = tk.Label(generate_key_page_frame, text=" ", font=("Arial", 12))
label_welcome.pack()

label_foldername = tk.Label(generate_key_page_frame, text="Nama Folder:")
label_foldername.pack()

entry_foldername = tk.Entry(generate_key_page_frame)
entry_foldername.pack()

button_select_folder = tk.Button(generate_key_page_frame, text="Pilih Folder", command=select_folder)
button_select_folder.pack()

label_filename = tk.Label(generate_key_page_frame, text="Nama File Kunci:")
label_filename.pack()

entry_filename = tk.Entry(generate_key_page_frame)
entry_filename.pack()

button_generate_key = tk.Button(generate_key_page_frame, text="Buat Kunci", command=generate_key_pair)
button_generate_key.pack()

label_welcome = tk.Label(generate_key_page_frame, text=" ", font=("Arial", 12))
label_welcome.pack()

button_back = tk.Button(generate_key_page_frame, text="Kembali ke Homepage", command=show_homepage)
button_back.pack()

##########################################################################################################################################

label_welcome = tk.Label(encrypt_page_frame, text="EMBED YOUR ENCRYPTED IMAGE TO VIDEO", font=("Arial", 14))
label_welcome.pack()
label_welcome = tk.Label(encrypt_page_frame, text=" ", font=("Arial", 12))
label_welcome.pack()

label_plaintext = tk.Label(encrypt_page_frame, text="Plaintext:")
label_plaintext.pack()

entry_plaintext = tk.Text(encrypt_page_frame, height=3)
entry_plaintext.pack()

button_encrypt = tk.Button(encrypt_page_frame, text="Enkripsi", command=encrypt_text)
button_encrypt.pack()

label_ciphertext = tk.Label(encrypt_page_frame, text="Ciphertext:")
label_ciphertext.pack()

entry_ciphertext = tk.Text(encrypt_page_frame, height=4)
entry_ciphertext.pack()

button_embed_ciphertext = tk.Button(encrypt_page_frame, text="Simpan Gambar", command=embed_ciphertext)
button_embed_ciphertext.pack()

label_image_file = tk.Label(encrypt_page_frame, text="File Gambar:")
label_image_file.pack()

entry_image_file = tk.Entry(encrypt_page_frame)
entry_image_file.pack()

button_select_image_file = tk.Button(encrypt_page_frame, text="Pilih Gambar", command=select_image_file)
button_select_image_file.pack()

label_video_file = tk.Label(encrypt_page_frame, text="File Video:")
label_video_file.pack()

entry_video_file = tk.Entry(encrypt_page_frame)
entry_video_file.pack()

button_select_video_file = tk.Button(encrypt_page_frame, text="Pilih Video", command=select_video_file)
button_select_video_file.pack()

button_embed_image = tk.Button(encrypt_page_frame, text="Simpan Video", command=embed_image_in_video)
button_embed_image.pack()

label_welcome = tk.Label(encrypt_page_frame, text=" ", font=("Arial", 12))
label_welcome.pack()

button_back = tk.Button(encrypt_page_frame, text="Kembali ke Homepage", command=show_homepage)
button_back.pack()

##########################################################################################################################################

label_welcome = tk.Label(decrypt_page_frame, text="DECRYPT AND EXTRACT YOUR VIDEO TO IMAGE", font=("Arial", 14))
label_welcome.pack()
label_welcome = tk.Label(decrypt_page_frame, text=" ", font=("Arial", 12))
label_welcome.pack()

label_embeded_video_file = tk.Label(decrypt_page_frame, text="File Video:")
label_embeded_video_file.pack()

entry_embeded_video_file = tk.Entry(decrypt_page_frame)
entry_embeded_video_file.pack()

button_select_embeded_video_file = tk.Button(decrypt_page_frame, text="Pilih Embeded Video", command=select_embeded_video_file)
button_select_embeded_video_file.pack()

button_extract_image = tk.Button(decrypt_page_frame, text="Ekstrak Foto", command=extract_image_in_video)
button_extract_image.pack()

button_extract_ciphertext = tk.Button(decrypt_page_frame, text="Extraksi Ciphertext", command=extract_ciphertext)
button_extract_ciphertext.pack()

label_extracted_ciphertext = tk.Label(decrypt_page_frame, text="Ciphertext yang Diekstraksi:")
label_extracted_ciphertext.pack()

entry_extracted_ciphertext = tk.Text(decrypt_page_frame, height=4)
entry_extracted_ciphertext.pack()

button_decrypt = tk.Button(decrypt_page_frame, text="Dekripsi", command=decrypt_ciphertext)
button_decrypt.pack()

label_decrypted_text = tk.Label(decrypt_page_frame, text="Ciphertext yang Didekripsi:")
label_decrypted_text.pack()

entry_decrypted_text = tk.Text(decrypt_page_frame, height=3)
entry_decrypted_text.pack()

label_welcome = tk.Label(decrypt_page_frame, text=" ", font=("Arial", 12))
label_welcome.pack()

button_back = tk.Button(decrypt_page_frame, text="Kembali ke Homepage", command=show_homepage)
button_back.pack()

# Show the homepage initially
show_homepage()

window.mainloop()
