import hashlib
import os

# --- KONFIGURASI ---
# (Pastikan nama ini SAMA dengan file database-mu, misal "DB.txt" atau "virus_db.txt")
DATABASE_FILE = "DB.txt" 

def hitung_sha256(file_path):
    """
    Membaca file sepotong demi sepotong (chunks) dan menghitung hash SHA-256.
    (Fungsi ini sama persis seperti sebelumnya)
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

    except FileNotFoundError:
        # Ini jarang terjadi jika os.walk menemukannya, tapi bagus untuk keamanan
        return "Error: File tidak ditemukan." 
    except PermissionError:
        # Ini akan sering terjadi pada file sistem yang terkunci
        print(f"-> [IZIN DITOLAK]: Tidak bisa mengakses {file_path}")
        return None # Kembalikan 'None' agar kita bisa melewatinya
    except Exception as e:
        print(f"-> [ERROR FILE]: {e}")
        return None # Kembalikan 'None' agar kita bisa melewatinya

def muat_database(path_db):
    """
    Membaca file database (baris demi baris) dan memuatnya ke dalam 'set'.
    (Fungsi ini sama persis seperti sebelumnya)
    """
    database_jahat = set()
    try:
        with open(path_db, "r") as db:
            for baris in db:
                database_jahat.add(baris.strip()) 
    except FileNotFoundError:
        print(f"!!! KRITIS: File database '{path_db}' tidak ditemukan. Program berhenti.")
        exit() # BARU: Kita hentikan program jika database tidak ada
    except Exception as e:
        print(f"Error saat memuat database: {e}")
        exit()
    
    return database_jahat

# --- Fungsi Utama Program ---
def main():
    print("--- Pemindai Folder v3.0 (Rekursif) ---")
    
    # 1. Muat database virus ke memori
    print(f"Memuat database dari: {DATABASE_FILE}")
    database_jahat = muat_database(DATABASE_FILE)
    if not database_jahat:
        print("Database kosong atau gagal dimuat. Keluar.")
        return
        
    print(f"Berhasil memuat {len(database_jahat)} tanda tangan (hash) virus.")
    
    # 2. BARU: Minta input FOLDER dari pengguna
    path_folder_input = input("\nMasukkan path lengkap ke FOLDER yang ingin dipindai: ")
    path_folder_bersih = path_folder_input.strip().strip('"')

    if not os.path.isdir(path_folder_bersih):
        print(f"Path yang Anda masukkan bukan FOLDER yang valid: {path_folder_bersih}")
        return

    print(f"\n--- MEMULAI PEMINDAIAN DI: {path_folder_bersih} ---")

    # 3. BARU: Siapkan penghitung
    total_file_dipindai = 0
    total_file_terinfeksi = 0
    daftar_file_terinfeksi = []

    # 4. BARU: Loop Rekursif menggunakan os.walk
    # os.walk akan menjelajahi setiap folder dan sub-folder
    # root: Folder saat ini (misal: 'D:\folderku')
    # dirs: Daftar sub-folder di dalam root (misal: ['folder_anak'])
    # files: Daftar file di dalam root (misal: ['teks.txt', 'foto.jpg'])
    for root, dirs, files in os.walk(path_folder_bersih):
        for nama_file in files:
            # Gabungkan path folder (root) dengan nama file
            file_path_lengkap = os.path.join(root, nama_file)
            
            # Coba hitung hash-nya
            hash_file = hitung_sha256(file_path_lengkap)
            total_file_dipindai += 1

            # Jika hash_file adalah None (karena error izin, dll), lewati saja
            if hash_file is None:
                continue
            
            # 5. BARU: Bandingkan hash file dengan database
            if hash_file in database_jahat:
                print(f"!!! TERDETEKSI: {file_path_lengkap}")
                total_file_terinfeksi += 1
                daftar_file_terinfeksi.append(file_path_lengkap)
            else:
                # Kita bisa tambahkan print di sini jika ingin lihat semua file
                # print(f"-> [AMAN]: {file_path_lengkap}")
                pass # Lewati saja jika aman agar output bersih
    
    # 6. BARU: Tampilkan Laporan Ringkasan
    print("\n" + "="*50)
    print("--- LAPORAN PEMINDAIAN SELESAI ---")
    print(f"Total File Dipindai     : {total_file_dipindai}")
    print(f"Total File Terinfeksi : {total_file_terinfeksi}")
    
    if total_file_terinfeksi > 0:
        print("\nLokasi File Terinfeksi:")
        for lokasi_file in daftar_file_terinfeksi:
            print(f"- {lokasi_file}")
    
    print("="*50 + "\n")


# Jalankan fungsi utama saat script dieksekusi
if __name__ == "__main__":
    main()