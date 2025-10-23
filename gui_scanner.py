import hashlib
import os
import tkinter as tk  # BARU: Mengimpor library GUI
from tkinter import filedialog  # BARU: Untuk dialog "pilih folder"
from tkinter import scrolledtext # BARU: Untuk area teks hasil yang bisa di-scroll

# --- KONFIGURASI ---
# (Pastikan nama ini SAMA dengan file database-mu)
DATABASE_FILE = "DB.txt" 
database_jahat = set() # BARU: Jadikan variabel global agar bisa diakses di mana saja

# ======================================================================
# --- LOGIKA MESIN PEMINDAI (Sama seperti sebelumnya) ---
# Kita letakkan semua fungsi inti kita di sini
# ======================================================================

def hitung_sha256(file_path):
    """
    Membaca file sepotong demi sepotong (chunks) dan menghitung hash SHA-256.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(4096)
            while chunk:
                sha256_hash.update(chunk)
                chunk = f.read(4096)
        
        hasil_hash = sha256_hash.hexdigest()
        return hasil_hash

    except PermissionError:
        # Kita akan cetak ini ke area teks GUI nanti
        return "Error: Izin Ditolak" 
    except Exception as e:
        return f"Error: {e}"

def muat_database(path_db):
    """
    Memuat database hash ke dalam 'set' global.
    """
    global database_jahat # BARU: Bilang kita mau ubah variabel global
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
# --- LOGIKA BARU UNTUK GUI ---
# Fungsi-fungsi yang akan dipanggil oleh tombol-tombol
# ======================================================================

def pilih_folder():
    """
    Dipanggil oleh tombol 'Pilih Folder'.
    Membuka dialog 'pilih folder' Windows dan menyimpan path-nya.
    """
    # Buka dialog dan simpan hasilnya di 'folder_dipilih'
    folder_dipilih = filedialog.askdirectory()
    
    if folder_dipilih:
        # Perbarui teks di kotak input (Entry)
        # Hapus dulu apa pun yang ada di sana
        entry_path_folder.delete(0, tk.END) 
        # Masukkan path yang baru dipilih
        entry_path_folder.insert(0, folder_dipilih)
        log(f"Folder dipilih: {folder_dipilih}")

def log(pesan):
    """Fungsi bantuan untuk mencetak pesan ke area teks GUI."""
    # 'state=tk.NORMAL' agar kita bisa menulis di dalamnya
    area_teks_hasil.config(state=tk.NORMAL)
    # Masukkan pesan di akhir, diikuti baris baru
    area_teks_hasil.insert(tk.END, pesan + "\n")
    # 'state=tk.DISABLED' agar pengguna tidak bisa mengetik di dalamnya
    area_teks_hasil.config(state=tk.DISABLED)
    # Otomatis scroll ke bawah
    area_teks_hasil.see(tk.END)

def mulai_pindai():
    """
    Fungsi utama yang dipanggil oleh tombol 'MULAI PINDAI'.
    Ini akan menjalankan logika pemindaian kita.
    """
    # 1. Bersihkan area log lama
    area_teks_hasil.config(state=tk.NORMAL)
    area_teks_hasil.delete(1.0, tk.END) # Hapus semua teks
    area_teks_hasil.config(state=tk.DISABLED)

    # 2. Muat database (jika belum)
    if not database_jahat:
        log("Memuat database...")
        pesan_db = muat_database(DATABASE_FILE)
        log(pesan_db)
        if "KRITIS" in pesan_db:
            return
            
    # 3. Dapatkan folder yang akan dipindai dari kotak input
    path_folder = entry_path_folder.get()
    
    if not path_folder or not os.path.isdir(path_folder):
        log(f"Path folder tidak valid: {path_folder}")
        return

    log(f"\n--- MEMULAI PEMINDAIAN DI: {path_folder} ---")

    # 4. Siapkan penghitung
    total_file_dipindai = 0
    total_file_terinfeksi = 0
    daftar_file_terinfeksi = [] # <-- BARU: Buat daftar kosong

    # 5. Jalankan loop os.walk (logika inti kita)
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
                daftar_file_terinfeksi.append(file_path_lengkap) # <-- BARU: Tambahkan ke daftar
            
            if total_file_dipindai % 100 == 0:
                jendela.update_idletasks()

    # 6. Tampilkan Laporan Ringkasan
    log("\n" + "="*50)
    log("--- LAPORAN PEMINDAIAN SELESAI ---")
    log(f"Total File Dipindai     : {total_file_dipindai}")
    log(f"Total File Terinfeksi : {total_file_terinfeksi}")
    
    # <-- BLOK BARU: Tampilkan daftar file terinfeksi -->
    if total_file_terinfeksi > 0:
        log("\nDaftar File Terinfeksi:")
        for lokasi_file in daftar_file_terinfeksi:
            log(f"- {lokasi_file}")
    # <-- Akhir Blok Baru -->
    
    log("="*50 + "\n")

# ======================================================================
# --- SETUP GUI TKINTER (Bagian 'Tampilan') ---
# ======================================================================

# 1. Buat Jendela Utama
jendela = tk.Tk()
jendela.title("Pemindai AntiVirus v0.1")
jendela.geometry("700x500") # Ukuran jendela (Lebar x Tinggi)

# 2. Buat Frame (kontainer) untuk bagian input
frame_input = tk.Frame(jendela)
frame_input.pack(pady=10) # .pack() menaruh elemen di jendela

# 3. Buat Label
label_folder = tk.Label(frame_input, text="Folder untuk Dipindai:")
label_folder.pack(side=tk.LEFT, padx=5)

# 4. Buat Kotak Input Teks (Entry)
entry_path_folder = tk.Entry(frame_input, width=60)
entry_path_folder.pack(side=tk.LEFT, padx=5)

# 5. Buat Tombol "Pilih Folder"
tombol_pilih = tk.Button(frame_input, text="Pilih Folder...", command=pilih_folder)
tombol_pilih.pack(side=tk.LEFT, padx=5)

# 6. Buat Tombol "Mulai Pindai"
tombol_pindai = tk.Button(jendela, text="MULAI PINDAI", 
                          command=mulai_pindai, 
                          font=("Arial", 12, "bold"), 
                          bg="red", fg="white")
tombol_pindai.pack(pady=10, fill=tk.X, padx=20)

# 7. Buat Area Teks Hasil (dengan Scrollbar)
area_teks_hasil = scrolledtext.ScrolledText(jendela, wrap=tk.WORD, 
                                            state=tk.DISABLED, 
                                            width=80, height=25)
area_teks_hasil.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

# 8. Jalankan aplikasi GUI
log("Memuat database saat aplikasi dimulai...")
pesan = muat_database(DATABASE_FILE)
log(pesan)
log("Silakan pilih folder dan klik 'MULAI PINDAI'.")

jendela.mainloop() # Ini akan menjaga jendela tetap terbuka