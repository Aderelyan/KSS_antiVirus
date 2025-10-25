import hashlib
import os
import shutil
import threading
import queue
import sqlite3  # BARU: Impor database SQL
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# --- KONFIGURASI ---
DATABASE_FILE = "antivirus.db" # DIUBAH: Nama file database baru
KARANTINA_DIR = "karantina/"

# ======================================================================
# --- KELAS LOGIKA PEMINDAI (Mesin) ---
# REFACTOR BESAR DI SINI
# ======================================================================
class Scanner:
    def __init__(self, db_path):
        self.db_path = db_path
        # Hapus 'self.database_jahat' dan 'muat_database()'
        self._init_db() # Panggil fungsi inisialisasi DB

    def _create_connection(self):
        """Menciptakan koneksi BARU ke database. Wajib untuk tiap thread."""
        try:
            # timeout 10 detik jika DB terkunci
            return sqlite3.connect(self.db_path, timeout=10) 
        except Exception as e:
            print(f"FATAL DB ERROR: {e}") # Cetak ke konsol jika GUI belum siap
            return None

    def _init_db(self):
        """Membuat tabel 'signatures' jika belum ada."""
        conn = self._create_connection()
        if not conn: return
        try:
            with conn: # 'with conn' akan otomatis commit atau rollback
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sha256 TEXT NOT NULL UNIQUE,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)
        except Exception as e:
            print(f"Error saat inisialisasi DB: {e}")
        finally:
            conn.close()

    def hitung_sha256(self, file_path):
        # (Fungsi ini tidak berubah)
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

    def _check_hash(self, conn, hash_file):
        """Internal: Memeriksa hash di DB menggunakan koneksi yang ada."""
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM signatures WHERE sha256 = ?", (hash_file,))
            return cursor.fetchone() is not None
        except Exception as e:
            print(f"Error saat _check_hash: {e}")
            return False

    def tambah_hash(self, hash_file):
        """Menambahkan hash baru ke DB. Mengembalikan True jika berhasil."""
        conn = self._create_connection()
        if not conn: return False, "Gagal terhubung ke DB"
        try:
            with conn:
                cursor = conn.cursor()
                # 'OR IGNORE' akan mencegah error jika hash sudah ada (UNIQUE)
                cursor.execute("INSERT OR IGNORE INTO signatures (sha256) VALUES (?)", (hash_file.strip(),))
                
                # 'conn.total_changes' akan > 0 HANYA jika baris baru ditambahkan
                if conn.total_changes > 0:
                    return True, "Hash berhasil ditambahkan."
                else:
                    return False, "Hash sudah ada di database."
        except Exception as e:
            return False, f"Error SQL: {e}"
        finally:
            conn.close()

    def pindai_folder(self, folder_path, progress_queue, cancel_event):
        """
        Memindai folder menggunakan koneksi DB yang dibuat oleh thread ini.
        """
        # Setiap thread HARUS membuat koneksi DB-nya sendiri
        conn = self._create_connection()
        if not conn:
            progress_queue.put("FATAL_ERROR: Tidak bisa terhubung ke database.")
            return

        try:
            # --- TAHAP 1: Menghitung Total File ---
            progress_queue.put("STATUS: Menghitung total file...")
            total_file = 0
            for root, dirs, files in os.walk(folder_path):
                if cancel_event.is_set():
                    progress_queue.put("DIBATALKAN: Pemindaian dibatalkan saat menghitung.")
                    return
                total_file += len(files)
            
            progress_queue.put(f"TOTAL_FILES:{total_file}")
            if total_file == 0:
                progress_queue.put("SELESAI: Tidak ada file ditemukan.")
                return

            # --- TAHAP 2: Memindai File ---
            progress_queue.put(f"STATUS: Memulai pemindaian {total_file} file...")
            total_terinfeksi = 0
            file_dipindai = 0

            for root, dirs, files in os.walk(folder_path):
                for nama_file in files:
                    if cancel_event.is_set():
                        progress_queue.put("DIBATALKAN: Pemindaian dibatalkan oleh pengguna.")
                        return

                    file_path_lengkap = os.path.join(root, nama_file)
                    file_dipindai += 1
                    
                    hash_file = self.hitung_sha256(file_path_lengkap)

                    if "Error:" in str(hash_file):
                        progress_queue.put(f"ERROR: {file_path_lengkap} ({hash_file})")
                    
                    # DIUBAH: Periksa hash langsung ke DB
                    elif self._check_hash(conn, hash_file):
                        total_terinfeksi += 1
                        progress_queue.put(f"TERDETEKSI: {file_path_lengkap}")
                    
                    progress_queue.put("PROGRESS:1")

            progress_queue.put(f"SELESAI: Total Dipindai: {file_dipindai}, Terinfeksi: {total_terinfeksi}")

        except Exception as e:
            progress_queue.put(f"FATAL_ERROR: {e}")
        finally:
            if conn:
                conn.close() # Tutup koneksi DB thread ini

# ======================================================================
# --- KELAS APLIKASI GUI (Tampilan) ---
# Perubahan pada Tab Pindai dan Tab Database
# ======================================================================
class AntivirusApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero") 
        self.title("Pemindai AntiVirus v2.3 (SQLite)")
        self.geometry("800x700")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.scanner = Scanner(DATABASE_FILE) # DIUBAH: Ini sekarang hanya inisialisasi
        self.scan_thread = None
        self.progress_queue = queue.Queue()
        self.cancel_event = threading.Event()

        self.buat_widget()
        self.proses_antrian()

        # DIUBAH: Log startup
        self.log(f"Database SQLite terinisialisasi di '{DATABASE_FILE}'")
        self.log("Silakan pilih folder dan klik 'MULAI PINDAI'.")
        self.muat_daftar_karantina()

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
        self.buat_tab_database(tab_database) # DIUBAH: Fungsi ini sekarang berisi widget

    def buat_tab_pindai(self, tab):
        """Mengisi tab Pindai (Tombol Tambah Virus DIHAPUS)"""
        
        # DIUBAH: Konfigurasi grid di DALAM tab pindai
        tab.grid_rowconfigure(4, weight=1) # Listbox
        tab.grid_rowconfigure(8, weight=1) # Log (sebelumnya 9)
        tab.grid_columnconfigure(0, weight=1)

        # Baris 0: Input (Sama)
        frame_input = ttk.Frame(tab)
        frame_input.grid(row=0, column=0, sticky=EW, pady=(0, 10))
        frame_input.grid_columnconfigure(1, weight=1)
        ttk.Label(frame_input, text="Folder:").grid(row=0, column=0, padx=5)
        self.entry_path_folder = ttk.Entry(frame_input, width=70)
        self.entry_path_folder.grid(row=0, column=1, padx=5, sticky=EW)
        self.tombol_pilih = ttk.Button(frame_input, text="Pilih Folder...", 
                                      command=self.pilih_folder, style="info.TButton")
        self.tombol_pilih.grid(row=0, column=2, padx=5)

        # Baris 1: Pindai (Sama)
        self.tombol_pindai = ttk.Button(tab, text="MULAI PINDAI",
                                        command=self.mulai_pindai_thread, style="danger.TButton")
        self.tombol_pindai.grid(row=1, column=0, padx=0, pady=5, sticky=EW, ipady=5)
        
        # Baris 2: Batal (Sama)
        self.tombol_batal = ttk.Button(tab, text="Batalkan Pemindaian", 
                                       command=self.batalkan_pemindaian,
                                       style="danger.outline.TButton")
        self.tombol_batal.grid(row=2, column=0, padx=0, pady=5, sticky=EW, ipady=5)
        self.tombol_batal.grid_remove()

        # Baris 3: Progress Bar (Sama)
        self.progressbar = ttk.Progressbar(tab, mode='determinate')
        self.progressbar.grid(row=3, column=0, padx=0, pady=10, sticky=EW)

        # Baris 4: Label Infeksi (Sama)
        ttk.Label(tab, text="File Terinfeksi (Ctrl/Shift-klik untuk Multi-Pilih):").grid(row=4, column=0, pady=(10,0), sticky=W)
        
        # Baris 5: Listbox (DIUBAH: row)
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

        # Baris 6: Tombol Aksi Karantina (DIUBAH: row)
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

        # BARIS 7: Tombol Tambah Virus DIHAPUS DARI SINI

        # Baris 7: Log Label (DIUBAH: row)
        ttk.Label(tab, text="Log Aktivitas:").grid(row=7, column=0, pady=(10,0), sticky=W)

        # Baris 8: Log Text (DIUBAH: row)
        frame_log = ttk.Frame(tab)
        frame_log.grid(row=8, column=0, padx=0, pady=5, sticky=NSEW)
        frame_log.grid_rowconfigure(0, weight=1)
        frame_log.grid_columnconfigure(0, weight=1)
        log_scrollbar = ttk.Scrollbar(frame_log, orient=VERTICAL)
        self.area_teks_log = ttk.Text(frame_log, wrap=WORD, 
                                     state=DISABLED, height=10, 
                                     yscrollcommand=log_scrollbar.set)
        log_scrollbar.config(command=self.area_teks_log.yview)
        log_scrollbar.grid(row=0, column=1, sticky=NS)
        self.area_teks_log.grid(row=0, column=0, sticky=NSEW)

    def buat_tab_karantina(self, tab):
        # (Fungsi ini tidak berubah)
        tab.grid_rowconfigure(2, weight=1) # DIUBAH: Koreksi baris weight
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
        tombol_hapus.grid(row=3, column=1, padx=(5,0), pady=10, sticky=EW, ipady=5) # DIUBAH: Koreksi grid

    def buat_tab_database(self, tab):
        """DIUBAH: Mengisi tab Database dengan widget."""
        tab.grid_columnconfigure(0, weight=1)

        # BARU: Menambahkan tombol "Tambah Virus" di sini
        ttk.Label(tab, text="Tambah Tanda Tangan (Hash) Virus Secara Manual").grid(row=0, column=0, pady=(10,5), padx=10, sticky=W)
        
        self.tombol_tambah_virus = ttk.Button(tab, text="Pilih File untuk Ditambah ke Database",
                                              command=self.tambah_virus_file,
                                              style="info.TButton")
        self.tombol_tambah_virus.grid(row=1, column=0, padx=10, pady=5, sticky=EW, ipady=5)
        
        ttk.Label(tab, text="Log aktivitas penambahan DB akan muncul di Tab 'Pindai'").grid(row=2, column=0, pady=(10,5), padx=10, sticky=W)
        
    # --- FUNGSI EVENT HANDLER & LOGIKA ---

    def mulai_pindai_thread(self):
        # (DIUBAH: Nonaktifkan tombol tambah virus di tab lain)
        path_folder = self.entry_path_folder.get()
        if not path_folder or not os.path.isdir(path_folder):
            self.log(f"Path folder tidak valid: {path_folder}")
            return
        
        self.log("\n" + "="*50)
        self.area_teks_log.config(state=NORMAL)
        self.listbox_terinfeksi.delete(0, END)
        self.area_teks_log.config(state=DISABLED)

        self.cancel_event.clear()
        self.progressbar.config(value=0, maximum=100)
        
        self.tombol_pilih.config(state=DISABLED)
        self.tombol_karantina.config(state=DISABLED)
        self.tombol_karantina_semua.config(state=DISABLED)
        self.tombol_tambah_virus.config(state=DISABLED) # Tombol di tab database
        
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
        self.tombol_karantina.config(state=NORMAL)
        self.tombol_karantina_semua.config(state=NORMAL)
        self.tombol_tambah_virus.config(state=NORMAL) # Tombol di tab database
        
        self.tombol_batal.grid_remove()
        self.tombol_batal.config(state=NORMAL, text="Batalkan Pemindaian")
        self.tombol_pindai.grid()

    # DIUBAH: Fungsi tambah_virus_action diperbarui untuk SQLite
    def tambah_virus_action(self, file_path):
        """
        Langkah 2: Dijalankan di Background Thread.
        Menghitung hash dan memanggil self.scanner.tambah_hash()
        """
        try:
            hash_file = self.scanner.hitung_sha256(file_path)
            
            if "Error:" in str(hash_file):
                self.progress_queue.put(f"ERROR: Gagal menghash {file_path}. {hash_file}")
                return

            # Panggil fungsi scanner yang baru (yang menjalankan SQL)
            sukses, pesan = self.scanner.tambah_hash(hash_file)
            
            if sukses:
                self.progress_queue.put(f"SUKSES_TAMBAH: Hash untuk '{os.path.basename(file_path)}' ditambahkan.")
            else:
                self.progress_queue.put(f"INFO: {pesan}")

        except Exception as e:
            self.progress_queue.put(f"ERROR: Gagal menambah file ke DB: {e}")
        finally:
            self.progress_queue.put("SELESAI_TAMBAH_VIRUS") # Sinyal untuk aktifkan tombol
    
    def log(self, pesan):
        """Menulis pesan ke area log GUI dengan aman."""
        try:
            self.area_teks_log.config(state=NORMAL)
            self.area_teks_log.insert(END, pesan + "\n")
            self.area_teks_log.config(state=DISABLED)
            self.area_teks_log.see(END)
        except Exception as e:
            # Jika log dipanggil sebelum area_teks_log dibuat
            print(f"Gagal mencatat log GUI: {e}")

    def proses_antrian(self):
        """DIUBAH: Menangani pesan SUKSES_TAMBAH baru"""
        try:
            pesan = self.progress_queue.get_nowait()
            
            if pesan.startswith("TOTAL_FILES:"):
                total = int(pesan.split(":")[1])
                self.progressbar.config(maximum=total if total > 0 else 100) # Hindari max 0
            elif pesan.startswith("PROGRESS:"):
                jumlah = int(pesan.split(":")[1])
                self.progressbar.step(jumlah)
            elif pesan.startswith("TERDETEKSI: "):
                path_file = pesan.replace("TERDETEKSI: ", "")
                self.listbox_terinfeksi.insert(END, path_file)
                self.log(pesan)
            elif pesan.startswith("SELESAI:"):
                self.selesaikan_pemindaian(pesan)
            elif pesan.startswith("DIBATALKAN:"):
                self.selesaikan_pemindaian(pesan)
            
            # DIUBAH: Cara menangani log tambah virus
            elif pesan.startswith("SUKSES_TAMBAH:"):
                self.log(pesan)
            elif pesan.startswith("INFO:"):
                self.log(pesan)
            elif pesan == "SELESAI_TAMBAH_VIRUS":
                self.tombol_tambah_virus.config(state=NORMAL)
            
            else:
                self.log(pesan)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.proses_antrian)

    # --- SISA FUNGSI (Karantina, Tambah Virus, dll) TIDAK BERUBAH ---
    # (Tidak ada perubahan logika di fungsi-fungsi di bawah ini)
    def pilih_folder(self):
        folder_dipilih = filedialog.askdirectory() 
        if folder_dipilih:
            self.entry_path_folder.delete(0, END)
            self.entry_path_folder.insert(0, folder_dipilih)
            self.log(f"Folder dipilih: {folder_dipilih}")

    def muat_daftar_karantina(self):
        try:
            if not hasattr(self, 'listbox_karantina'): return
            self.listbox_karantina.delete(0, END)
            if not os.path.exists(KARANTINA_DIR):
                os.makedirs(KARANTINA_DIR)
                self.log(f"Folder karantina '{KARANTINA_DIR}' dibuat.")
                return
            files = os.listdir(KARANTINA_DIR)
            if not files:
                self.listbox_karantina.insert(END, "(Karantina kosong)")
                self.log("Folder karantina kosong.")
            else:
                for f in files: self.listbox_karantina.insert(END, f)
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
                    self.log(f"GAGAL PULIH: File '{nama_file}' sudah ada di tujuan. Dilewati.")
                    gagal += 1
                    continue
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
                self.listbox_terinfeksi.delete(indeks)
                sukses += 1
            except Exception as e:
                self.log(f"GAGAL (Terpilih): Gagal karantina '{path_file_terinfeksi}'. Error: {e}")
                gagal += 1
        self.log(f"Karantina terpilih selesai: {sukses} berhasil, {gagal} gagal.")
        self.muat_daftar_karantina()

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
                self.listbox_terinfeksi.delete(indeks)
                sukses += 1
            except Exception as e:
                self.log(f"GAGAL (Semua): Gagal karantina '{path_file_terinfeksi}'. Error: {e}")
                gagal += 1
        self.log(f"Karantina total selesai: {sukses} berhasil, {gagal} gagal.")
        self.muat_daftar_karantina()

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
        self.log(f"Menghitung hash untuk {os.path.basename(file_path)}...")
        threading.Thread(
            target=self.tambah_virus_action, 
            args=(file_path,), 
            daemon=True
        ).start()
            
# ======================================================================
# --- Titik Masuk Program ---
# ======================================================================
if __name__ == "__main__":
    app = AntivirusApp()
    app.mainloop()