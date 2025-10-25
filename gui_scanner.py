import hashlib
import os
import shutil  # BARU: Library untuk memindahkan file
import tkinter as tk
from tkinter import filedialog, messagebox, ttk  # BARU: Import messagebox dan ttk

# --- KONFIGURASI ---
DATABASE_FILE = "DB.txt" 
KARANTINA_DIR = "karantina/"  # BARU: Nama folder untuk karantina
database_jahat = set()

# ======================================================================
# --- LOGIKA MESIN PEMINDAI (Sama seperti sebelumnya) ---
# ======================================================================

def hitung_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(4096)
            while chunk:
                sha256_hash.update(chunk)
                chunk = f.read(4096)
        return sha256_hash.hexdigest()
    except PermissionError:
        return "Error: Izin Ditolak"
    except Exception as e:
        return f"Error: {e}"

def muat_database(path_db):
    global database_jahat
    database_jahat.clear() # BARU: Bersihkan dulu jika dipanggil lagi
    try:
        with open(path_db, "r") as db:
            for baris in db:
                database_jahat.add(baris.strip())
        if not database_jahat:
            return "Peringatan: Database kosong."
        else:
            return f"Berhasil memuat {len(database_jahat)} tanda tangan (hash) virus."
    except FileNotFoundError:
        return f"!!! KRITIS: File database '{path_db}' tidak ditemukan."
    except Exception as e:
        return f"Error saat memuat database: {e}"

# ======================================================================
# --- LOGIKA BARU UNTUK GUI & KARANTINA ---
# ======================================================================

def pilih_folder():
    folder_dipilih = filedialog.askdirectory()
    if folder_dipilih:
        entry_path_folder.delete(0, tk.END)
        entry_path_folder.insert(0, folder_dipilih)
        log(f"Folder dipilih: {folder_dipilih}")

def log(pesan):
    """Fungsi bantuan untuk mencetak pesan ke area log (di bawah)"""
    area_teks_log.config(state=tk.NORMAL)
    area_teks_log.insert(tk.END, pesan + "\n")
    area_teks_log.config(state=tk.DISABLED)
    area_teks_log.see(tk.END)

def mulai_pindai():
    # 1. Bersihkan area log dan daftar infeksi lama
    area_teks_log.config(state=tk.NORMAL)
    area_teks_log.delete(1.0, tk.END)
    area_teks_log.config(state=tk.DISABLED)
    listbox_terinfeksi.delete(0, tk.END) # BARU: Bersihkan listbox

    # 2. Muat database
    log("Memuat ulang database...")
    pesan_db = muat_database(DATABASE_FILE)
    log(pesan_db)
    if "KRITIS" in pesan_db:
        return
            
    # 3. Dapatkan folder yang akan dipindai
    path_folder = entry_path_folder.get()
    if not path_folder or not os.path.isdir(path_folder):
        log(f"Path folder tidak valid: {path_folder}")
        return

    log(f"\n--- MEMULAI PEMINDAIAN DI: {path_folder} ---")

    # 4. Siapkan penghitung
    total_file_dipindai = 0
    total_file_terinfeksi = 0

    # 5. Jalankan loop os.walk
    for root, dirs, files in os.walk(path_folder):
        for nama_file in files:
            file_path_lengkap = os.path.join(root, nama_file)
            
            hash_file = hitung_sha256(file_path_lengkap)
            total_file_dipindai += 1

            if "Error:" in str(hash_file):
                log(f"-> [ERROR]: {file_path_lengkap} ({hash_file})")
                continue
            
            if hash_file in database_jahat:
                log(f"!!! TERDETEKSI: {file_path_lengkap}")
                total_file_terinfeksi += 1
                # BARU: Tambahkan HANYA file terinfeksi ke Listbox
                listbox_terinfeksi.insert(tk.END, file_path_lengkap)
            
            if total_file_dipindai % 100 == 0:
                log(f"Telah memindai {total_file_dipindai} file...")
                jendela.update_idletasks() # Beri 'napas' pada GUI

    # 6. Tampilkan Laporan Ringkasan
    log("\n" + "="*50)
    log("--- LAPORAN PEMINDAIAN SELESAI ---")
    log(f"Total File Dipindai     : {total_file_dipindai}")
    log(f"Total File Terinfeksi : {total_file_terinfeksi}")
    if total_file_terinfeksi > 0:
        log("Periksa daftar 'File Terinfeksi' di atas untuk tindakan.")
    log("="*50 + "\n")

# BARU: Fungsi yang dipanggil tombol karantina
def karantina_file_terpilih():
    """Memindahkan file yang dipilih di Listbox ke folder karantina."""
    
    # 1. Dapatkan file yang dipilih dari Listbox
    try:
        # Dapatkan indeks dari item yang dipilih
        indeks_terpilih = listbox_terinfeksi.curselection()[0]
        # Dapatkan teks (path file) dari indeks itu
        path_file_terinfeksi = listbox_terinfeksi.get(indeks_terpilih)
    except IndexError:
        # Terjadi jika pengguna mengklik tombol tanpa memilih file
        messagebox.showwarning("Tidak Ada Pilihan", "Silakan pilih file dari daftar terinfeksi terlebih dahulu.")
        return

    # 2. Buat folder karantina jika belum ada
    try:
        if not os.path.exists(KARANTINA_DIR):
            os.makedirs(KARANTINA_DIR)
            log(f"Folder '{KARANTINA_DIR}' dibuat.")
    except Exception as e:
        messagebox.showerror("Error Folder", f"Gagal membuat folder karantina: {e}")
        return

    # 3. Pindahkan file
    try:
        # Dapatkan nama file saja (misal: 'test.txt')
        nama_file = os.path.basename(path_file_terinfeksi)
        # Buat path tujuan (misal: 'karantina/test.txt')
        path_tujuan = os.path.join(KARANTINA_DIR, nama_file)
        
        # Pindahkan file!
        shutil.move(path_file_terinfeksi, path_tujuan)
        
        # 4. Update GUI setelah berhasil
        log(f"BERHASIL: File '{nama_file}' telah dikarantina ke '{path_tujuan}'.")
        # Hapus file dari Listbox
        listbox_terinfeksi.delete(indeks_terpilih)
        
    except Exception as e:
        log(f"GAGAL: Tidak bisa mengarantina '{path_file_terinfeksi}'. Error: {e}")
        messagebox.showerror("Error Karantina", f"Tidak bisa memindahkan file: {e}\n(Mungkin file sedang digunakan?)")


# ======================================================================
# --- SETUP GUI TKINTER (Tampilan Baru) ---
# ======================================================================

# 1. Buat Jendela Utama
jendela = tk.Tk()
jendela.title("Pemindai AntiVirus v0.2 - Karantina")
jendela.geometry("800x600") # Ukuran jendela diperbesar

# 2. Frame Input (Sama seperti sebelumnya)
frame_input = tk.Frame(jendela)
frame_input.pack(pady=10, fill=tk.X, padx=20)

label_folder = tk.Label(frame_input, text="Folder untuk Dipindai:")
label_folder.pack(side=tk.LEFT, padx=5)

entry_path_folder = tk.Entry(frame_input, width=70) # Sedikit lebih lebar
entry_path_folder.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

tombol_pilih = tk.Button(frame_input, text="Pilih Folder...", command=pilih_folder)
tombol_pilih.pack(side=tk.LEFT, padx=5)

# 3. Tombol Pindai (Sama seperti sebelumnya)
tombol_pindai = tk.Button(jendela, text="MULAI PINDAI", 
                          command=mulai_pindai, 
                          font=("Arial", 12, "bold"), 
                          bg="red", fg="white")
tombol_pindai.pack(pady=5, fill=tk.X, padx=20)

# --- BAGIAN BARU: Tampilan dibagi dua ---

# 4. Buat Label untuk daftar terinfeksi
label_terinfeksi = tk.Label(jendela, text="File Terinfeksi (Pilih untuk Karantina):", font=("Arial", 10, "bold"))
label_terinfeksi.pack(padx=20, pady=(10,0), anchor=tk.W) # anchor=W (West/Barat) = rata kiri

# 5. Buat Listbox untuk file terinfeksi
frame_listbox = tk.Frame(jendela)
frame_listbox.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)

scrollbar_listbox = tk.Scrollbar(frame_listbox, orient=tk.VERTICAL)
listbox_terinfeksi = tk.Listbox(frame_listbox, yscrollcommand=scrollbar_listbox.set, height=10)
scrollbar_listbox.config(command=listbox_terinfeksi.yview)

scrollbar_listbox.pack(side=tk.RIGHT, fill=tk.Y)
listbox_terinfeksi.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# 6. Buat Tombol Karantina BARU
tombol_karantina = tk.Button(jendela, text="Karantina File Terpilih", 
                             command=karantina_file_terpilih, 
                             bg="orange", fg="black")
tombol_karantina.pack(pady=5, fill=tk.X, padx=20)

# 7. Buat Label untuk Log
label_log = tk.Label(jendela, text="Log Aktivitas:", font=("Arial", 10, "bold"))
label_log.pack(padx=20, pady=(10,0), anchor=tk.W)

# 8. Buat Area Teks Log (ScrolledText)
# (Ini yang sebelumnya kita pakai untuk semua, sekarang hanya untuk log)
area_teks_log = tk.Text(jendela, wrap=tk.WORD, 
                        state=tk.DISABLED, 
                        height=10) # Lebih pendek
area_teks_log.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)

# 9. Jalankan aplikasi
pesan = muat_database(DATABASE_FILE)
log(pesan)
log("Silakan pilih folder dan klik 'MULAI PINDAI'.")

jendela.mainloop()