import hashlib
import os
import shutil
import threading
import queue
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox # Pastikan messagebox & filedialog diimpor dari tkinter
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# --- IMPOR BARU UNTUK HAK AKSES ADMIN ---
import ctypes
import sys
# ----------------------------------------

# --- KONFIGURASI ---
DATABASE_FILE = "antivirus.db"
KARANTINA_DIR = "karantina/" # Pastikan diakhiri dengan /

# ======================================================================
# --- FUNGSI BARU UNTUK CEK ADMIN ---
# ======================================================================
def is_admin():
    """Memeriksa apakah skrip sedang berjalan dengan hak akses Admin."""
    try:
        # Panggil fungsi Windows API 'IsUserAnAdmin'
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ======================================================================
# --- KELAS LOGIKA PEMINDAI (Mesin) ---
# ======================================================================
class Scanner:
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_db()

    def _create_connection(self):
        """Menciptakan koneksi BARU ke database. Wajib untuk tiap thread."""
        try:
            # timeout 10 detik jika DB terkunci
            return sqlite3.connect(self.db_path, timeout=10)
        except Exception as e:
            print(f"FATAL DB ERROR: {e}") # Cetak ke konsol jika GUI belum siap
            return None

    def _init_db(self):
        """Membuat tabel 'signatures' dengan kolom md5 DAN sha256 jika belum ada."""
        conn = self._create_connection()
        if not conn: return
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        md5 TEXT NOT NULL UNIQUE,
                        sha256 TEXT NOT NULL UNIQUE,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
        except Exception as e:
            print(f"Error saat inisialisasi DB: {e}")
        finally:
            conn.close()

    def _hitung_hashes(self, file_path):
        """Menghitung MD5 dan SHA256 sekaligus agar efisien."""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(4096)
                while chunk:
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
                    chunk = f.read(4096)
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except PermissionError:
            return "Error: Izin Ditolak", None
        except Exception as e:
            return f"Error: {e}", None

    def _check_hash(self, conn, hash_md5, hash_sha256):
        """Memeriksa apakah SALAH SATU hash ada di DB."""
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM signatures WHERE md5 = ? OR sha256 = ?", (hash_md5, hash_sha256))
            return cursor.fetchone() is not None
        except Exception as e:
            print(f"Error saat _check_hash: {e}")
            return False

    def tambah_hash(self, hash_md5, hash_sha256):
        """Menambahkan KEDUA hash ke DB."""
        conn = self._create_connection()
        if not conn: return False, "Gagal terhubung ke DB"
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("INSERT OR IGNORE INTO signatures (md5, sha256) VALUES (?, ?)",
                               (hash_md5.strip(), hash_sha256.strip()))
                if conn.total_changes > 0:
                    return True, "Hash berhasil ditambahkan."
                else:
                    return False, "Hash (MD5 atau SHA256) sudah ada di database."
        except Exception as e:
            return False, f"Error SQL: {e}"
        finally:
            conn.close()

    def pindai_folder(self, folder_path, progress_queue, cancel_event):
        """
        Memindai folder menggunakan koneksi DB yang dibuat oleh thread ini.
        Dengan penanganan error os.walk yang lebih baik.
        """
        conn = self._create_connection()
        if not conn:
            progress_queue.put("FATAL_ERROR: Tidak bisa terhubung ke database.")
            return

        total_file = 0
        total_terinfeksi = 0
        file_dipindai = 0

        try:
            # --- TAHAP 1: Menghitung Total File ---
            progress_queue.put("STATUS: Menghitung total file...")
            try: # Tangkap error saat os.walk dimulai
                # onerror=None akan mencoba melanjutkan jika subfolder error
                for root, dirs, files in os.walk(folder_path, topdown=True, onerror=None):
                    if cancel_event.is_set():
                        progress_queue.put("DIBATALKAN: Pemindaian dibatalkan saat menghitung.")
                        return
                    # Tangkap error jika tidak bisa mengakses isi folder
                    try:
                        total_file += len(files)
                    except PermissionError:
                        progress_queue.put(f"ERROR_HITUNG: Izin ditolak untuk folder {root}")
                    except OSError as e: # Tangkap error lain saat akses direktori
                         progress_queue.put(f"ERROR_HITUNG: Gagal akses {root} - {e}")

            except PermissionError: # Tangkap error jika os.walk gagal masuk folder awal
                progress_queue.put(f"FATAL_ERROR: Izin ditolak untuk mengakses folder utama: {folder_path}")
                return
            except Exception as e: # Tangkap error tak terduga lainnya dari os.walk
                progress_queue.put(f"FATAL_ERROR: Gagal saat menghitung file: {e}")
                return

            progress_queue.put(f"TOTAL_FILES:{total_file}")
            if total_file == 0:
                progress_queue.put("SELESAI: Tidak ada file ditemukan atau bisa diakses.")
                return

            # --- TAHAP 2: Memindai File ---
            progress_queue.put(f"STATUS: Memulai pemindaian {total_file} file...")
            try: # Tangkap error saat os.walk dimulai (lagi)
                for root, dirs, files in os.walk(folder_path, topdown=True, onerror=None):
                    if cancel_event.is_set():
                        progress_queue.put("DIBATALKAN: Pemindaian dibatalkan oleh pengguna.")
                        return

                    # Tangkap error jika tidak bisa mengakses isi folder
                    try:
                        for nama_file in files:
                            if cancel_event.is_set():
                                progress_queue.put("DIBATALKAN: Pemindaian dibatalkan oleh pengguna.")
                                return

                            file_path_lengkap = os.path.join(root, nama_file)
                            file_dipindai += 1
                            hash_md5, hash_sha256 = self._hitung_hashes(file_path_lengkap)

                            if hash_sha256 is None: # Error saat hashing
                                progress_queue.put(f"ERROR_HASH: {file_path_lengkap} ({hash_md5})") # hash_md5 berisi pesan error
                            elif self._check_hash(conn, hash_md5, hash_sha256):
                                total_terinfeksi += 1
                                progress_queue.put(f"TERDETEKSI: {file_path_lengkap}")

                            # Kirim progres setiap file
                            progress_queue.put("PROGRESS:1")

                    except PermissionError:
                        progress_queue.put(f"ERROR_PINDAI: Izin ditolak untuk file di {root}")
                    except OSError as e: # Tangkap error lain saat akses file
                         progress_queue.put(f"ERROR_PINDAI: Gagal akses file di {root} - {e}")

            except PermissionError: # Tangkap error jika os.walk gagal masuk folder awal
                progress_queue.put(f"FATAL_ERROR: Izin ditolak untuk mengakses folder utama: {folder_path}")
                return
            except Exception as e: # Tangkap error tak terduga lainnya dari os.walk
                progress_queue.put(f"FATAL_ERROR: Gagal saat memindai file: {e}")
                return

            progress_queue.put(f"SELESAI: Total Dipindai: {file_dipindai}, Terinfeksi: {total_terinfeksi}")

        finally: # Pastikan koneksi DB selalu ditutup
            if conn:
                conn.close()

# ======================================================================
# --- KELAS APLIKASI GUI (Tampilan) ---
# ======================================================================
class AntivirusApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Pemindai AntiVirus KSS v2.6 (Admin)") # Ganti KSS jika perlu
        self.geometry("800x700")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.scanner = Scanner(DATABASE_FILE)
        self.scan_thread = None
        self.progress_queue = queue.Queue()
        self.cancel_event = threading.Event()

        self.buat_widget()
        self.proses_antrian()

        # Tambahkan status Admin ke judul
        if is_admin():
            self.title(self.title() + " [ADMINISTRATOR]")
            # Log awal dipindahkan ke sini agar area_teks_log sudah ada
            self.log(f"Berjalan dengan Hak Akses Administrator.")
        else:
            self.log("Berjalan dengan Hak Akses Pengguna Standar.")

        self.log(f"Database SQLite terinisialisasi di '{DATABASE_FILE}'")
        self.log("Silakan pilih folder dan klik 'MULAI PINDAI'.")
        self.muat_daftar_karantina() # Muat daftar karantina saat startup

    def buat_widget(self):
        notebook = ttk.Notebook(self)
        notebook.grid(row=0, column=0, sticky=NSEW, padx=10, pady=10)

        tab_pindai = ttk.Frame(notebook, padding=10)
        tab_karantina = ttk.Frame(notebook, padding=10)
        tab_database = ttk.Frame(notebook, padding=10)

        notebook.add(tab_pindai, text="Pindai")
        notebook.add(tab_karantina, text="Manajemen Karantina")
        notebook.add(tab_database, text="Manajemen Database")

        self.buat_tab_pindai(tab_pindai)
        self.buat_tab_karantina(tab_karantina)
        self.buat_tab_database(tab_database)

    def buat_tab_pindai(self, tab):
        tab.grid_rowconfigure(5, weight=1) # Listbox (sebelumnya 4)
        tab.grid_rowconfigure(9, weight=1) # Log (sebelumnya 8)
        tab.grid_columnconfigure(0, weight=1)

        # Baris 0: Input
        frame_input = ttk.Frame(tab)
        frame_input.grid(row=0, column=0, sticky=EW, pady=(0, 10))
        frame_input.grid_columnconfigure(1, weight=1)
        ttk.Label(frame_input, text="Folder:").grid(row=0, column=0, padx=5)
        self.entry_path_folder = ttk.Entry(frame_input, width=70)
        self.entry_path_folder.grid(row=0, column=1, padx=5, sticky=EW)
        self.tombol_pilih = ttk.Button(frame_input, text="Pilih Folder...",
                                      command=self.pilih_folder, style="info.TButton")
        self.tombol_pilih.grid(row=0, column=2, padx=5)

        # Baris 1: Pindai
        self.tombol_pindai = ttk.Button(tab, text="MULAI PINDAI",
                                        command=self.mulai_pindai_thread, style="danger.TButton")
        self.tombol_pindai.grid(row=1, column=0, padx=0, pady=5, sticky=EW, ipady=5)

        # Baris 2: Batal
        self.tombol_batal = ttk.Button(tab, text="Batalkan Pemindaian",
                                       command=self.batalkan_pemindaian,
                                       style="danger.outline.TButton")
        self.tombol_batal.grid(row=2, column=0, padx=0, pady=5, sticky=EW, ipady=5)
        self.tombol_batal.grid_remove() # Sembunyikan

        # Baris 3: Progress Bar
        self.progressbar = ttk.Progressbar(tab, mode='determinate')
        self.progressbar.grid(row=3, column=0, padx=0, pady=10, sticky=EW)

        # Baris 4: Label Infeksi
        ttk.Label(tab, text="File Terinfeksi (Ctrl/Shift-klik untuk Multi-Pilih):").grid(row=4, column=0, pady=(10,0), sticky=W)

        # Baris 5: Listbox Infeksi
        frame_listbox = ttk.Frame(tab)
        frame_listbox.grid(row=5, column=0, padx=0, pady=5, sticky=NSEW)
        frame_listbox.grid_rowconfigure(0, weight=1)
        frame_listbox.grid_columnconfigure(0, weight=1)
        scrollbar_y = ttk.Scrollbar(frame_listbox, orient=VERTICAL)
        self.listbox_terinfeksi = tk.Listbox(frame_listbox,
                                             yscrollcommand=scrollbar_y.set,
                                             height=10, selectmode=EXTENDED)
        scrollbar_y.config(command=self.listbox_terinfeksi.yview)
        scrollbar_y.grid(row=0, column=1, sticky=NS)
        self.listbox_terinfeksi.grid(row=0, column=0, sticky=NSEW)

        # Baris 6: Tombol Aksi Karantina
        frame_tombol_aksi = ttk.Frame(tab)
        frame_tombol_aksi.grid(row=6, column=0, padx=0, pady=0, sticky=EW)
        frame_tombol_aksi.grid_columnconfigure((0, 1), weight=1)
        self.tombol_karantina = ttk.Button(frame_tombol_aksi, text="Karantina Terpilih",
                                           command=self.karantina_file_terpilih,
                                           style="warning.outline.TButton")
        self.tombol_karantina.grid(row=0, column=0, padx=0, pady=5, sticky=EW, ipady=5)
        self.tombol_karantina_semua = ttk.Button(frame_tombol_aksi, text="Karantina Semua",
                                                 command=self.karantina_semua,
                                                 style="warning.TButton")
        self.tombol_karantina_semua.grid(row=0, column=1, padx=(5,0), pady=5, sticky=EW, ipady=5)

        # Baris 7: Log Label
        ttk.Label(tab, text="Log Aktivitas Pindai:").grid(row=8, column=0, pady=(10,0), sticky=W) # Koreksi row

        # Baris 8: Log Text
        frame_log = ttk.Frame(tab)
        frame_log.grid(row=9, column=0, padx=0, pady=5, sticky=NSEW) # Koreksi row
        frame_log.grid_rowconfigure(0, weight=1)
        frame_log.grid_columnconfigure(0, weight=1)
        log_scrollbar = ttk.Scrollbar(frame_log, orient=VERTICAL)
        # Pastikan area log ini dibuat sebelum log() dipanggil di __init__
        self.area_teks_log = ttk.Text(frame_log, wrap=WORD,
                                     state=DISABLED, height=10,
                                     yscrollcommand=log_scrollbar.set)
        log_scrollbar.config(command=self.area_teks_log.yview)
        log_scrollbar.grid(row=0, column=1, sticky=NS)
        self.area_teks_log.grid(row=0, column=0, sticky=NSEW)

    def buat_tab_karantina(self, tab):
        tab.grid_rowconfigure(2, weight=1) # Baris Listbox
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)

        tombol_refresh_karantina = ttk.Button(tab, text="Refresh Daftar",
                                               command=self.muat_daftar_karantina,
                                               style="info.TButton")
        tombol_refresh_karantina.grid(row=0, column=0, columnspan=2, padx=0, pady=10, sticky=EW)

        ttk.Label(tab, text="File di Karantina (Ctrl/Shift-klik untuk Multi-Pilih):").grid(row=1, column=0, columnspan=2, padx=0, pady=(5,0), sticky=W)

        frame_list_karantina = ttk.Frame(tab)
        frame_list_karantina.grid(row=2, column=0, columnspan=2, padx=0, pady=5, sticky=NSEW)
        frame_list_karantina.grid_rowconfigure(0, weight=1)
        frame_list_karantina.grid_columnconfigure(0, weight=1)
        scrollbar_karantina = ttk.Scrollbar(frame_list_karantina, orient=VERTICAL)
        self.listbox_karantina = tk.Listbox(frame_list_karantina,
                                            yscrollcommand=scrollbar_karantina.set,
                                            height=15, selectmode=EXTENDED)
        scrollbar_karantina.config(command=self.listbox_karantina.yview)
        scrollbar_karantina.grid(row=0, column=1, sticky=NS)
        self.listbox_karantina.grid(row=0, column=0, sticky=NSEW)

        tombol_pulihkan = ttk.Button(tab, text="Pulihkan Terpilih",
                                     command=self.pulihkan_file_terpilih,
                                     style="success.outline.TButton")
        tombol_pulihkan.grid(row=3, column=0, padx=(0,5), pady=10, sticky=EW, ipady=5)
        tombol_hapus = ttk.Button(tab, text="Hapus Permanen Terpilih",
                                  command=self.hapus_permanen_terpilih,
                                  style="danger.outline.TButton")
        tombol_hapus.grid(row=3, column=1, padx=(5,0), pady=10, sticky=EW, ipady=5)

    def buat_tab_database(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(3, weight=1) # Baris Log DB

        ttk.Label(tab, text="Tambah Tanda Tangan (Hash) Virus Secara Manual").grid(row=0, column=0, pady=(10,5), padx=10, sticky=W)
        self.tombol_tambah_virus = ttk.Button(tab, text="Pilih File untuk Ditambah ke Database",
                                              command=self.tambah_virus_file,
                                              style="info.TButton")
        self.tombol_tambah_virus.grid(row=1, column=0, padx=10, pady=5, sticky=EW, ipady=5)

        ttk.Label(tab, text="Log Aktivitas Database:").grid(row=2, column=0, pady=(10,0), padx=10, sticky=W)
        frame_log_db = ttk.Frame(tab)
        frame_log_db.grid(row=3, column=0, padx=10, pady=5, sticky=NSEW)
        frame_log_db.grid_rowconfigure(0, weight=1)
        frame_log_db.grid_columnconfigure(0, weight=1)
        log_db_scrollbar = ttk.Scrollbar(frame_log_db, orient=VERTICAL)
        # Pastikan area log DB ini dibuat sebelum log_db() dipanggil
        self.area_teks_log_db = ttk.Text(frame_log_db, wrap=WORD,
                                         state=DISABLED, height=10,
                                         yscrollcommand=log_db_scrollbar.set)
        log_db_scrollbar.config(command=self.area_teks_log_db.yview)
        log_db_scrollbar.grid(row=0, column=1, sticky=NS)
        self.area_teks_log_db.grid(row=0, column=0, sticky=NSEW)

    # --- FUNGSI EVENT HANDLER & LOGIKA ---

    # Fungsi log() HARUS ada di sini
    def log(self, pesan):
        """Menulis pesan ke log Pindai (Tab 1)."""
        # Tambahkan pengecekan apakah widget sudah dibuat
        if hasattr(self, 'area_teks_log'):
            try:
                self.area_teks_log.config(state=NORMAL)
                self.area_teks_log.insert(END, pesan + "\n")
                self.area_teks_log.config(state=DISABLED)
                self.area_teks_log.see(END)
            except Exception as e:
                print(f"Gagal mencatat log Pindai: {e}")
        else:
             print(f"Log Pindai (menunggu GUI): {pesan}") # Cetak ke konsol jika GUI belum siap

    # Fungsi log_db() HARUS ada di sini
    def log_db(self, pesan):
        """Menulis pesan ke log Database (Tab 3)."""
        # Tambahkan pengecekan apakah widget sudah dibuat
        if hasattr(self, 'area_teks_log_db'):
            try:
                self.area_teks_log_db.config(state=NORMAL)
                self.area_teks_log_db.insert(END, pesan + "\n")
                self.area_teks_log_db.config(state=DISABLED)
                self.area_teks_log_db.see(END)
            except Exception as e:
                print(f"Gagal mencatat log DB: {e}")
        else:
            print(f"Log DB (menunggu GUI): {pesan}")

    # Fungsi pilih_folder() HARUS ada di sini
    def pilih_folder(self):
        folder_dipilih = filedialog.askdirectory()
        if folder_dipilih:
            # Pastikan entry widget sudah ada
            if hasattr(self, 'entry_path_folder'):
                self.entry_path_folder.delete(0, END)
                self.entry_path_folder.insert(0, folder_dipilih)
            self.log(f"Folder dipilih: {folder_dipilih}")

    def mulai_pindai_thread(self):
        path_folder = self.entry_path_folder.get()
        if not path_folder or not os.path.isdir(path_folder):
            self.log(f"Path folder tidak valid: {path_folder}")
            return
        self.log("\n" + "="*50 + f"\n--- MEMULAI PEMINDAIAN DI: {path_folder} ---")
        self.listbox_terinfeksi.delete(0, END)
        self.cancel_event.clear()
        self.progressbar.config(value=0, maximum=100)
        self.tombol_pilih.config(state=DISABLED)
        self.tombol_karantina.config(state=DISABLED)
        self.tombol_karantina_semua.config(state=DISABLED)
        self.tombol_tambah_virus.config(state=DISABLED)
        self.tombol_pindai.grid_remove()
        self.tombol_batal.grid()
        self.scan_thread = threading.Thread(
            target=self.scanner.pindai_folder,
            args=(path_folder, self.progress_queue, self.cancel_event),
            daemon=True
        )
        self.scan_thread.start()

    def batalkan_pemindaian(self):
        self.log("SINYAL BATAL: Meminta pemindaian untuk berhenti...")
        self.cancel_event.set()
        self.tombol_batal.config(state=DISABLED, text="Membatalkan...")

    def selesaikan_pemindaian(self, pesan_log=""):
        if pesan_log:
            self.log(pesan_log)
            self.log("="*50 + "\n")
        self.progressbar.config(value=0)
        self.tombol_pilih.config(state=NORMAL)
        # Aktifkan tombol karantina hanya jika ada item terdeteksi
        if self.listbox_terinfeksi.size() > 0:
            self.tombol_karantina.config(state=NORMAL)
            self.tombol_karantina_semua.config(state=NORMAL)
        else:
             self.tombol_karantina.config(state=DISABLED)
             self.tombol_karantina_semua.config(state=DISABLED)
        self.tombol_tambah_virus.config(state=NORMAL)
        self.tombol_batal.grid_remove()
        self.tombol_batal.config(state=NORMAL, text="Batalkan Pemindaian")
        self.tombol_pindai.grid()

    def tambah_virus_action(self, file_path):
        try:
            hash_md5, hash_sha256 = self.scanner._hitung_hashes(file_path)
            if hash_sha256 is None:
                self.progress_queue.put(f"DB_ERROR: Gagal menghash {file_path}. {hash_md5}")
                return
            sukses, pesan = self.scanner.tambah_hash(hash_md5, hash_sha256)
            if sukses:
                self.progress_queue.put(f"DB_SUKSES: Hash untuk '{os.path.basename(file_path)}' ditambahkan.")
                self.progress_queue.put(f"DB_INFO: MD5: {hash_md5}")
                self.progress_queue.put(f"DB_INFO: SHA256: {hash_sha256}")
            else:
                self.progress_queue.put(f"DB_INFO: {pesan}")
        except Exception as e:
            self.progress_queue.put(f"DB_ERROR: Gagal menambah file ke DB: {e}")
        finally:
            self.progress_queue.put("DB_SELESAI_TAMBAH_VIRUS")

    def proses_antrian(self):
        try:
            while True: # Proses semua pesan di antrian sekaligus
                pesan = self.progress_queue.get_nowait()

                # --- Pesan untuk Log Pindai (self.log) ---
                if pesan.startswith(("TOTAL_FILES:", "PROGRESS:", "TERDETEKSI:", "STATUS:", "ERROR:", "FATAL_ERROR:", "ERROR_HITUNG:", "ERROR_PINDAI:", "ERROR_HASH:")):
                    self.log(pesan)
                    if pesan.startswith("TOTAL_FILES:"):
                        total = int(pesan.split(":")[1])
                        self.progressbar.config(maximum=total if total > 0 else 100)
                    elif pesan.startswith("PROGRESS:"):
                        self.progressbar.step(int(pesan.split(":")[1]))
                    elif pesan.startswith("TERDETEKSI:"):
                        self.listbox_terinfeksi.insert(END, pesan.replace("TERDETEKSI: ", ""))
                elif pesan.startswith("SELESAI:"):
                    self.selesaikan_pemindaian(pesan)
                elif pesan.startswith("DIBATALKAN:"):
                    self.selesaikan_pemindaian(pesan)

                # --- Pesan untuk Log Database (self.log_db) ---
                elif pesan.startswith("DB_SUKSES:"):
                    self.log_db(pesan.replace("DB_SUKSES: ", ""))
                elif pesan.startswith("DB_INFO:"):
                    self.log_db(pesan.replace("DB_INFO: ", ""))
                elif pesan.startswith("DB_ERROR:"):
                    self.log_db(pesan.replace("DB_ERROR: ", ""))
                elif pesan == "DB_SELESAI_TAMBAH_VIRUS":
                    self.tombol_tambah_virus.config(state=NORMAL)
                    self.log_db("Siap menambah file baru...")

                else:
                    # Pesan lain yang tidak dikenal
                    self.log(f"Pesan Antrian Tdk Dikenal: {pesan}")

        except queue.Empty: # Antrian kosong, berhenti memproses
            pass
        finally:
            self.after(100, self.proses_antrian) # Jadwalkan cek lagi

    def muat_daftar_karantina(self):
        # Pastikan widget sudah ada sebelum mencoba menggunakannya
        if not hasattr(self, 'listbox_karantina'):
             self.after(200, self.muat_daftar_karantina) # Coba lagi nanti
             return
        try:
            self.listbox_karantina.delete(0, END)
            if not os.path.exists(KARANTINA_DIR):
                os.makedirs(KARANTINA_DIR)
                self.log(f"Folder karantina '{KARANTINA_DIR}' dibuat.")
                self.listbox_karantina.insert(END, "(Karantina kosong)") # Tambahkan pesan jika baru dibuat
                return
            files = os.listdir(KARANTINA_DIR)
            if not files:
                self.listbox_karantina.insert(END, "(Karantina kosong)")
                self.log("Folder karantina kosong.")
            else:
                for f in sorted(files): self.listbox_karantina.insert(END, f) # Urutkan file
                self.log(f"Berhasil memuat {len(files)} file dari karantina.")
        except Exception as e:
            self.log(f"ERROR: Gagal memuat daftar karantina: {e}")
            if hasattr(self, 'listbox_karantina'): self.listbox_karantina.insert(END, f"Error: {e}")

    def pulihkan_file_terpilih(self):
        indeks_terpilih = self.listbox_karantina.curselection()
        if not indeks_terpilih:
            messagebox.showwarning("Tidak Ada Pilihan", "Pilih file dari daftar karantina untuk dipulihkan.")
            return
        folder_tujuan = filedialog.askdirectory(title="Pilih folder tujuan untuk memulihkan file")
        if not folder_tujuan: return
        sukses = 0; gagal = 0
        for indeks in sorted(indeks_terpilih, reverse=True):
            try:
                nama_file = self.listbox_karantina.get(indeks)
                path_sumber = os.path.join(KARANTINA_DIR, nama_file)
                path_tujuan = os.path.join(folder_tujuan, nama_file)
                if os.path.exists(path_tujuan):
                    konfirmasi_timpa = messagebox.askyesno("Konfirmasi Timpa", f"File '{nama_file}' sudah ada di tujuan.\nTimpa file tersebut?")
                    if not konfirmasi_timpa:
                        self.log(f"INFO PULIH: Pemulihan '{nama_file}' dibatalkan.")
                        continue # Lanjut ke file berikutnya
                shutil.move(path_sumber, path_tujuan)
                self.log(f"BERHASIL PULIH: File '{nama_file}' dipulihkan ke '{folder_tujuan}'.")
                self.listbox_karantina.delete(indeks)
                sukses += 1
            except Exception as e:
                self.log(f"GAGAL PULIH: Gagal memulihkan '{nama_file}'. Error: {e}")
                gagal += 1
        self.log(f"Pemulihan selesai: {sukses} berhasil, {gagal} gagal.")

    def hapus_permanen_terpilih(self):
        indeks_terpilih = self.listbox_karantina.curselection()
        if not indeks_terpilih:
            messagebox.showwarning("Tidak Ada Pilihan", "Pilih file dari daftar karantina untuk dihapus.")
            return
        konfirmasi = messagebox.askyesno("Konfirmasi Hapus Permanen",
                                            f"Anda yakin ingin menghapus {len(indeks_terpilih)} file ini secara permanen?\n\nTindakan ini tidak bisa dibatalkan.",
                                            icon='warning')
        if not konfirmasi: return
        sukses = 0; gagal = 0
        for indeks in sorted(indeks_terpilih, reverse=True):
            try:
                nama_file = self.listbox_karantina.get(indeks)
                path_file = os.path.join(KARANTINA_DIR, nama_file)
                os.remove(path_file)
                self.log(f"BERHASIL HAPUS: File '{nama_file}' telah dihapus permanen.")
                self.listbox_karantina.delete(indeks)
                sukses += 1
            except Exception as e:
                self.log(f"GAGAL HAPUS: Gagal menghapus '{nama_file}'. Error: {e}")
                gagal += 1
        self.log(f"Penghapusan selesai: {sukses} berhasil, {gagal} gagal.")

    def karantina_file_terpilih(self):
        indeks_terpilih = self.listbox_terinfeksi.curselection()
        if not indeks_terpilih:
            messagebox.showwarning("Tidak Ada Pilihan", "Pilih file dari daftar infeksi terlebih dahulu.")
            return
        if not self.pastikan_folder_karantina(): return
        sukses = 0; gagal = 0
        file_dipindah = [] # Tampung file yang berhasil dipindah
        for indeks in sorted(indeks_terpilih, reverse=True):
            try:
                path_file_terinfeksi = self.listbox_terinfeksi.get(indeks)
                nama_file = os.path.basename(path_file_terinfeksi)
                path_tujuan = os.path.join(KARANTINA_DIR, nama_file)
                if os.path.exists(path_tujuan):
                    self.log(f"GAGAL (Terpilih): File '{nama_file}' sudah ada di karantina. Dilewati.")
                    gagal += 1
                    continue
                shutil.move(path_file_terinfeksi, path_tujuan)
                self.log(f"BERHASIL (Terpilih): File '{nama_file}' telah dikarantina.")
                # Jangan hapus dari listbox dulu, kumpulkan indeksnya
                file_dipindah.append(indeks)
                sukses += 1
            except Exception as e:
                self.log(f"GAGAL (Terpilih): Gagal karantina '{path_file_terinfeksi}'. Error: {e}")
                gagal += 1
        # Hapus item yang berhasil dipindah dari listbox (dari belakang)
        for indeks in sorted(file_dipindah, reverse=True):
             self.listbox_terinfeksi.delete(indeks)
        self.log(f"Karantina terpilih selesai: {sukses} berhasil, {gagal} gagal.")
        if sukses > 0: self.muat_daftar_karantina() # Refresh tab karantina jika ada perubahan

    def karantina_semua(self):
        daftar_path = list(self.listbox_terinfeksi.get(0, END))
        if not daftar_path:
            messagebox.showinfo("Listbox Kosong", "Tidak ada file terdeteksi untuk dikarantina.")
            return
        jumlah = len(daftar_path)
        konfirmasi = messagebox.askyesno("Konfirmasi Karantina Semua",
                                            f"Anda yakin ingin mengarantina semua {jumlah} file yang terdeteksi?")
        if not konfirmasi: return
        if not self.pastikan_folder_karantina(): return
        self.log(f"Memulai karantina total {jumlah} file...")
        sukses = 0; gagal = 0
        file_dipindah = [] # Tampung file yang berhasil dipindah
        for indeks in range(jumlah - 1, -1, -1):
            try:
                path_file_terinfeksi = daftar_path[indeks]
                nama_file = os.path.basename(path_file_terinfeksi)
                path_tujuan = os.path.join(KARANTINA_DIR, nama_file)
                if os.path.exists(path_tujuan):
                    self.log(f"GAGAL (Semua): File '{nama_file}' sudah ada di karantina. Dilewati.")
                    gagal += 1
                    continue
                shutil.move(path_file_terinfeksi, path_tujuan)
                self.log(f"BERHASIL (Semua): File '{nama_file}' telah dikarantina.")
                # Jangan hapus dari listbox dulu, kumpulkan indeksnya
                file_dipindah.append(indeks)
                sukses += 1
            except Exception as e:
                self.log(f"GAGAL (Semua): Gagal karantina '{path_file_terinfeksi}'. Error: {e}")
                gagal += 1
        # Hapus item yang berhasil dipindah dari listbox (dari belakang)
        for indeks in sorted(file_dipindah, reverse=True):
             self.listbox_terinfeksi.delete(indeks)
        self.log(f"Karantina total selesai: {sukses} berhasil, {gagal} gagal.")
        if sukses > 0: self.muat_daftar_karantina() # Refresh tab karantina jika ada perubahan

    def pastikan_folder_karantina(self):
        try:
            if not os.path.exists(KARANTINA_DIR):
                os.makedirs(KARANTINA_DIR)
                self.log(f"Folder '{KARANTINA_DIR}' dibuat.")
            return True
        except Exception as e:
            messagebox.showerror("Error Folder", f"Gagal membuat folder karantina: {e}")
            return False

    def tambah_virus_file(self):
        file_path = filedialog.askopenfilename(title="Pilih file untuk ditambahkan ke database")
        if not file_path: return
        self.tombol_tambah_virus.config(state=DISABLED)
        self.log_db("Menghitung hash MD5 & SHA256...")
        threading.Thread(
            target=self.tambah_virus_action,
            args=(file_path,),
            daemon=True
        ).start()

# ======================================================================
# --- Titik Masuk Program ---
# ======================================================================
if __name__ == "__main__":
    if os.name == 'nt':
        if not is_admin():
            print("Meminta hak akses Administrator...")
            try:
                # Parameter untuk ShellExecuteW:
                # hwnd = None (tidak ada jendela induk)
                # lpOperation = "runas" (minta UAC)
                # lpFile = sys.executable (path ke python.exe)
                # lpParameters = " ".join(sys.argv) (path ke skrip ini)
                # lpDirectory = None (direktori kerja saat ini)
                # nShowCmd = 1 (SW_SHOWNORMAL)
                result = ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    sys.executable,
                    f'"{__file__}"', # Pastikan path skrip ada dalam tanda kutip
                    None,
                    1
                )
                if result <= 32: # Jika gagal (error code <= 32)
                     print(f"Gagal meminta hak akses (Error Code: {result}). Jalankan manual sebagai Admin.")
            except Exception as e:
                print(f"Gagal meminta hak akses: {e}. Jalankan manual sebagai Admin.")
            sys.exit(0) # Keluar dari proses non-admin

        # Jika sudah admin atau bukan Windows
        app = AntivirusApp()
        app.mainloop()

    else:
        # Jika bukan Windows
        app = AntivirusApp()
        app.mainloop()