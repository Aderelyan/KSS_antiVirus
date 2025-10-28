import os
import shutil
import threading
import queue
import sqlite3 # Masih diperlukan untuk error handling
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# --- IMPOR BARU ---
import ctypes
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
# --- IMPOR BARU DARI MODUL LOKAL ---
from scanner_logic import Scanner  # <- Impor kelas Scanner dari file lain
from utils import is_admin         # <- Impor fungsi is_admin dari file lain
# ------------------------------------

# --- KONFIGURASI ---
DATABASE_FILE = "antivirus.db"
KARANTINA_DIR = "karantina/"
MAX_DB_WORKERS = 5

# ======================================================================
# --- KELAS APLIKASI GUI (Tampilan) ---
# ======================================================================
class AntivirusApp(ttk.Window):
    def __init__(self):
        super().__init__(themename="superhero")
        self.title("Pemindai AntiVirus KSS v3.0 (Final + Delete)") # Versi baru
        self.geometry("800x700")
        self.grid_rowconfigure(0, weight=1); self.grid_columnconfigure(0, weight=1)

        self.scanner = Scanner(DATABASE_FILE)
        self.scan_thread = None; self.progress_queue = queue.Queue(); self.cancel_event = threading.Event()
        self.db_executor = ThreadPoolExecutor(max_workers=MAX_DB_WORKERS)

        self.buat_widget()
        self.proses_antrian()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        if is_admin(): self.title(self.title() + " [ADMINISTRATOR]"); self.log(f"Berjalan dengan Hak Akses Administrator.")
        else: self.log("Berjalan dengan Hak Akses Pengguna Standar.")
        self.log(f"Database SQLite terinisialisasi di '{DATABASE_FILE}'"); self.log("Silakan pilih folder dan klik 'MULAI PINDAI'.")
        self.muat_daftar_karantina(); self.muat_tampilan_database()

    def on_closing(self):
        print("Menutup aplikasi dan mematikan executor...")
        # Shutdown non-blocking agar UI cepat tertutup
        self.db_executor.shutdown(wait=False, cancel_futures=True)
        self.destroy()

    def buat_widget(self):
        notebook = ttk.Notebook(self); notebook.grid(row=0, column=0, sticky=NSEW, padx=10, pady=10)
        tab_pindai = ttk.Frame(notebook, padding=10); tab_karantina = ttk.Frame(notebook, padding=10); tab_database = ttk.Frame(notebook, padding=10)
        notebook.add(tab_pindai, text="Pindai"); notebook.add(tab_karantina, text="Manajemen Karantina"); notebook.add(tab_database, text="Manajemen Database")
        self.buat_tab_pindai(tab_pindai); self.buat_tab_karantina(tab_karantina); self.buat_tab_database(tab_database)

    def buat_tab_pindai(self, tab):
        # ... (Kode tab pindai tidak berubah) ...
        tab.grid_rowconfigure(5, weight=1); tab.grid_rowconfigure(9, weight=1); tab.grid_columnconfigure(0, weight=1)
        frame_input = ttk.Frame(tab); frame_input.grid(row=0, column=0, sticky=EW, pady=(0, 10)); frame_input.grid_columnconfigure(1, weight=1)
        ttk.Label(frame_input, text="Folder:").grid(row=0, column=0, padx=5)
        self.entry_path_folder = ttk.Entry(frame_input, width=70); self.entry_path_folder.grid(row=0, column=1, padx=5, sticky=EW)
        self.tombol_pilih = ttk.Button(frame_input, text="Pilih Folder...", command=self.pilih_folder, style="info.TButton"); self.tombol_pilih.grid(row=0, column=2, padx=5)
        self.tombol_pindai = ttk.Button(tab, text="MULAI PINDAI", command=self.mulai_pindai_thread, style="danger.TButton"); self.tombol_pindai.grid(row=1, column=0, padx=0, pady=5, sticky=EW, ipady=5)
        self.tombol_batal = ttk.Button(tab, text="Batalkan Pemindaian", command=self.batalkan_pemindaian, style="danger.outline.TButton"); self.tombol_batal.grid(row=2, column=0, padx=0, pady=5, sticky=EW, ipady=5); self.tombol_batal.grid_remove()
        self.progressbar = ttk.Progressbar(tab, mode='determinate'); self.progressbar.grid(row=3, column=0, padx=0, pady=10, sticky=EW)
        ttk.Label(tab, text="File Terinfeksi (Ctrl/Shift-klik untuk Multi-Pilih):").grid(row=4, column=0, pady=(10,0), sticky=W)
        frame_listbox = ttk.Frame(tab); frame_listbox.grid(row=5, column=0, padx=0, pady=5, sticky=NSEW); frame_listbox.grid_rowconfigure(0, weight=1); frame_listbox.grid_columnconfigure(0, weight=1)
        scrollbar_y = ttk.Scrollbar(frame_listbox, orient=VERTICAL)
        self.listbox_terinfeksi = tk.Listbox(frame_listbox, yscrollcommand=scrollbar_y.set, height=10, selectmode=EXTENDED); scrollbar_y.config(command=self.listbox_terinfeksi.yview); scrollbar_y.grid(row=0, column=1, sticky=NS); self.listbox_terinfeksi.grid(row=0, column=0, sticky=NSEW)
        frame_tombol_aksi = ttk.Frame(tab); frame_tombol_aksi.grid(row=6, column=0, padx=0, pady=0, sticky=EW); frame_tombol_aksi.grid_columnconfigure((0, 1), weight=1)
        self.tombol_karantina = ttk.Button(frame_tombol_aksi, text="Karantina Terpilih", command=self.karantina_file_terpilih, style="warning.outline.TButton"); self.tombol_karantina.grid(row=0, column=0, padx=0, pady=5, sticky=EW, ipady=5)
        self.tombol_karantina_semua = ttk.Button(frame_tombol_aksi, text="Karantina Semua", command=self.karantina_semua, style="warning.TButton"); self.tombol_karantina_semua.grid(row=0, column=1, padx=(5,0), pady=5, sticky=EW, ipady=5)
        ttk.Label(tab, text="Log Aktivitas Pindai:").grid(row=8, column=0, pady=(10,0), sticky=W)
        frame_log = ttk.Frame(tab); frame_log.grid(row=9, column=0, padx=0, pady=5, sticky=NSEW); frame_log.grid_rowconfigure(0, weight=1); frame_log.grid_columnconfigure(0, weight=1)
        log_scrollbar = ttk.Scrollbar(frame_log, orient=VERTICAL)
        self.area_teks_log = ttk.Text(frame_log, wrap=WORD, state=DISABLED, height=10, yscrollcommand=log_scrollbar.set); log_scrollbar.config(command=self.area_teks_log.yview); log_scrollbar.grid(row=0, column=1, sticky=NS); self.area_teks_log.grid(row=0, column=0, sticky=NSEW)

    def buat_tab_karantina(self, tab):
        # ... (Kode tab karantina tidak berubah) ...
        tab.grid_rowconfigure(2, weight=1); tab.grid_columnconfigure(0, weight=1); tab.grid_columnconfigure(1, weight=1)
        tombol_refresh_karantina = ttk.Button(tab, text="Refresh Daftar", command=self.muat_daftar_karantina, style="info.TButton"); tombol_refresh_karantina.grid(row=0, column=0, columnspan=2, padx=0, pady=10, sticky=EW)
        ttk.Label(tab, text="File di Karantina (Ctrl/Shift-klik untuk Multi-Pilih):").grid(row=1, column=0, columnspan=2, padx=0, pady=(5,0), sticky=W)
        frame_list_karantina = ttk.Frame(tab); frame_list_karantina.grid(row=2, column=0, columnspan=2, padx=0, pady=5, sticky=NSEW); frame_list_karantina.grid_rowconfigure(0, weight=1); frame_list_karantina.grid_columnconfigure(0, weight=1)
        scrollbar_karantina = ttk.Scrollbar(frame_list_karantina, orient=VERTICAL)
        self.listbox_karantina = tk.Listbox(frame_list_karantina, yscrollcommand=scrollbar_karantina.set, height=15, selectmode=EXTENDED); scrollbar_karantina.config(command=self.listbox_karantina.yview); scrollbar_karantina.grid(row=0, column=1, sticky=NS); self.listbox_karantina.grid(row=0, column=0, sticky=NSEW)
        tombol_pulihkan = ttk.Button(tab, text="Pulihkan Terpilih", command=self.pulihkan_file_terpilih, style="success.outline.TButton"); tombol_pulihkan.grid(row=3, column=0, padx=(0,5), pady=10, sticky=EW, ipady=5)
        tombol_hapus = ttk.Button(tab, text="Hapus Permanen Terpilih", command=self.hapus_permanen_terpilih, style="danger.outline.TButton"); tombol_hapus.grid(row=3, column=1, padx=(5,0), pady=10, sticky=EW, ipady=5)

    def buat_tab_database(self, tab):
        """DIUBAH LAGI: Menambahkan tombol Delete Hash."""
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(3, weight=1) # Treeview
        tab.grid_rowconfigure(6, weight=1) # Log DB

        # Baris 0 & 1: Tambah Virus
        ttk.Label(tab, text="Tambah Tanda Tangan (Hash) Virus Secara Manual").grid(row=0, column=0, pady=(10,5), padx=10, sticky=W)
        self.tombol_tambah_virus = ttk.Button(tab, text="Pilih File(s) untuk Ditambah ke Database", command=self.tambah_virus_file, style="info.TButton"); self.tombol_tambah_virus.grid(row=1, column=0, padx=10, pady=5, sticky=EW, ipady=5)

        # Baris 2: Label Treeview
        ttk.Label(tab, text="Isi Database Tanda Tangan Virus (Pilih baris untuk dihapus):").grid(row=2, column=0, pady=(15,0), padx=10, sticky=W) # Tambah instruksi

        # Baris 3: Treeview
        frame_tree = ttk.Frame(tab); frame_tree.grid(row=3, column=0, padx=10, pady=5, sticky=NSEW); frame_tree.grid_rowconfigure(0, weight=1); frame_tree.grid_columnconfigure(0, weight=1)
        tree_scroll_y = ttk.Scrollbar(frame_tree, orient=VERTICAL); tree_scroll_x = ttk.Scrollbar(frame_tree, orient=HORIZONTAL)
        kolom = ('id', 'md5', 'sha256', 'timestamp')
        self.db_treeview = ttk.Treeview(frame_tree, columns=kolom, show='headings', height=7, yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set); tree_scroll_y.config(command=self.db_treeview.yview); tree_scroll_x.config(command=self.db_treeview.xview)
        self.db_treeview.heading('id', text='ID'); self.db_treeview.heading('md5', text='MD5 Hash'); self.db_treeview.heading('sha256', text='SHA256 Hash'); self.db_treeview.heading('timestamp', text='Ditambahkan Pada')
        self.db_treeview.column('id', width=50, stretch=False, anchor=CENTER); self.db_treeview.column('md5', width=250, stretch=True); self.db_treeview.column('sha256', width=400, stretch=True); self.db_treeview.column('timestamp', width=150, stretch=False)
        self.db_treeview.grid(row=0, column=0, sticky=NSEW); tree_scroll_y.grid(row=0, column=1, sticky=NS); tree_scroll_x.grid(row=1, column=0, sticky=EW)

        # BARIS 4: Frame Tombol Refresh & Delete (INI YANG HILANG SEBELUMNYA)
        frame_db_actions = ttk.Frame(tab)
        frame_db_actions.grid(row=4, column=0, padx=10, pady=(5,10), sticky=EW)
        frame_db_actions.grid_columnconfigure(0, weight=1) # Tombol Refresh
        frame_db_actions.grid_columnconfigure(1, weight=1) # Tombol Delete

        tombol_refresh_db = ttk.Button(frame_db_actions, text="Refresh Tampilan Database", command=self.muat_tampilan_database, style="secondary.TButton")
        tombol_refresh_db.grid(row=0, column=0, padx=(0,5), sticky=EW, ipady=5)

        tombol_hapus_hash = ttk.Button(frame_db_actions, text="Hapus Hash Terpilih",
                                      command=self.delete_selected_hash, # Fungsi handler baru
                                      style="danger.outline.TButton")
        tombol_hapus_hash.grid(row=0, column=1, padx=(5,0), sticky=EW, ipady=5)
        # --- AKHIR BAGIAN YANG HILANG ---

        # Baris 5 & 6: Log Database
        ttk.Label(tab, text="Log Aktivitas Database:").grid(row=5, column=0, pady=(10,0), padx=10, sticky=W)
        frame_log_db = ttk.Frame(tab); frame_log_db.grid(row=6, column=0, padx=10, pady=5, sticky=NSEW); frame_log_db.grid_rowconfigure(0, weight=1); frame_log_db.grid_columnconfigure(0, weight=1)
        log_db_scrollbar = ttk.Scrollbar(frame_log_db, orient=VERTICAL)
        self.area_teks_log_db = ttk.Text(frame_log_db, wrap=WORD, state=DISABLED, height=5, yscrollcommand=log_db_scrollbar.set); log_db_scrollbar.config(command=self.area_teks_log_db.yview); log_db_scrollbar.grid(row=0, column=1, sticky=NS); self.area_teks_log_db.grid(row=0, column=0, sticky=NSEW)


    # --- FUNGSI EVENT HANDLER & LOGIKA ---

    def log(self, pesan):
        # ... (Sama seperti v2.9) ...
        if hasattr(self, 'area_teks_log'):
            try: waktu = datetime.now().strftime("[%H:%M:%S]"); pesan_log = f"{waktu} {pesan}"; self.area_teks_log.config(state=NORMAL); self.area_teks_log.insert(END, pesan_log + "\n"); self.area_teks_log.config(state=DISABLED); self.area_teks_log.see(END)
            except Exception as e: print(f"Gagal mencatat log Pindai: {e}")
        else: print(f"Log Pindai (menunggu GUI): {pesan}")

    def log_db(self, pesan):
        # ... (Sama seperti v2.9) ...
        if hasattr(self, 'area_teks_log_db'):
            try: waktu = datetime.now().strftime("[%H:%M:%S]"); pesan_log = f"{waktu} {pesan}"; self.area_teks_log_db.config(state=NORMAL); self.area_teks_log_db.insert(END, pesan_log + "\n"); self.area_teks_log_db.config(state=DISABLED); self.area_teks_log_db.see(END)
            except Exception as e: print(f"Gagal mencatat log DB: {e}")
        else: print(f"Log DB (menunggu GUI): {pesan}")

    def pilih_folder(self):
        # ... (Sama seperti v2.9) ...
        folder_dipilih = filedialog.askdirectory();
        if folder_dipilih:
            if hasattr(self, 'entry_path_folder'): self.entry_path_folder.delete(0, END); self.entry_path_folder.insert(0, folder_dipilih)
            self.log(f"Folder dipilih: {folder_dipilih}")

    def mulai_pindai_thread(self):
        # ... (Sama seperti v2.9) ...
        path_folder = self.entry_path_folder.get();
        if not path_folder or not os.path.isdir(path_folder): self.log(f"Path folder tidak valid: {path_folder}"); return
        self.log("\n" + "="*50 + f"\n--- MEMULAI PEMINDAIAN DI: {path_folder} ---")
        if hasattr(self, 'listbox_terinfeksi'): self.listbox_terinfeksi.delete(0, END);
        self.cancel_event.clear(); self.progressbar.config(value=0, maximum=100)
        if hasattr(self, 'tombol_pilih'): self.tombol_pilih.config(state=DISABLED)
        if hasattr(self, 'tombol_karantina'): self.tombol_karantina.config(state=DISABLED)
        if hasattr(self, 'tombol_karantina_semua'): self.tombol_karantina_semua.config(state=DISABLED)
        if hasattr(self, 'tombol_tambah_virus'): self.tombol_tambah_virus.config(state=DISABLED)
        self.tombol_pindai.grid_remove(); self.tombol_batal.grid()
        self.scan_thread = threading.Thread(target=self.scanner.pindai_folder, args=(path_folder, self.progress_queue, self.cancel_event), daemon=True); self.scan_thread.start()

    def batalkan_pemindaian(self):
        # ... (Sama seperti v2.9) ...
        self.log("SINYAL BATAL: Meminta pemindaian untuk berhenti..."); self.cancel_event.set(); self.tombol_batal.config(state=DISABLED, text="Membatalkan...")

    def selesaikan_pemindaian(self, pesan_log=""):
        # ... (Sama seperti v2.9) ...
        if pesan_log: self.log(pesan_log); self.log("="*50 + "\n")
        self.progressbar.config(value=0)
        if hasattr(self, 'tombol_pilih'): self.tombol_pilih.config(state=NORMAL)
        listbox_ada = hasattr(self, 'listbox_terinfeksi') and self.listbox_terinfeksi.size() > 0
        if hasattr(self, 'tombol_karantina'): self.tombol_karantina.config(state=NORMAL if listbox_ada else DISABLED)
        if hasattr(self, 'tombol_karantina_semua'): self.tombol_karantina_semua.config(state=NORMAL if listbox_ada else DISABLED)
        if hasattr(self, 'tombol_tambah_virus'): self.tombol_tambah_virus.config(state=NORMAL)
        self.tombol_batal.grid_remove(); self.tombol_batal.config(state=NORMAL, text="Batalkan Pemindaian"); self.tombol_pindai.grid()

    def tambah_virus_file(self):
        # ... (Sama seperti v2.9) ...
        file_paths = filedialog.askopenfilenames(title="Pilih SATU atau LEBIH file untuk ditambahkan ke database")
        if not file_paths: return
        jumlah_file = len(file_paths)
        if jumlah_file > 0:
            if hasattr(self, 'tombol_tambah_virus'): self.tombol_tambah_virus.config(state=DISABLED)
            self.log_db(f"Memulai proses penambahan {jumlah_file} file ke database...")
            for file_path in file_paths:
                self.log_db(f"--> Mengantrikan: {os.path.basename(file_path)}")
                self.db_executor.submit(self.tambah_virus_action, file_path)

    def tambah_virus_action(self, file_path):
        # ... (Sama seperti v2.9) ...
        try:
            hash_md5, hash_sha256 = self.scanner._hitung_hashes(file_path)
            if hash_sha256 is None: self.progress_queue.put(f"DB_ERROR: Gagal menghash '{os.path.basename(file_path)}'. {hash_md5}"); return
            sukses, pesan = self.scanner.tambah_hash(hash_md5, hash_sha256)
            nama_file = os.path.basename(file_path)
            if sukses: self.progress_queue.put(f"DB_SUKSES: Hash untuk '{nama_file}' ditambahkan."); self.progress_queue.put("DB_UPDATED")
            else: self.progress_queue.put(f"DB_INFO: Hash untuk '{nama_file}' sudah ada ({pesan})")
        except Exception as e: self.progress_queue.put(f"DB_ERROR: Gagal proses '{os.path.basename(file_path)}': {e}")
        finally: self.progress_queue.put("DB_SELESAI_TAMBAH_VIRUS")

    # --- FUNGSI BARU UNTUK MENGHAPUS HASH ---
    def delete_selected_hash(self):
        """Menghapus entri hash yang dipilih dari Treeview dan DB."""
        if not hasattr(self, 'db_treeview'): return # Pengaman jika treeview belum ada

        selected_items = self.db_treeview.selection()
        if not selected_items:
            messagebox.showwarning("Tidak Ada Pilihan", "Pilih satu atau lebih baris hash dari tabel untuk dihapus.")
            return

        ids_to_delete = []
        md5s_preview = []
        for item_id in selected_items:
            try:
                values = self.db_treeview.item(item_id, 'values')
                if values and len(values) > 1: # Pastikan ada nilai dan minimal ada ID & MD5
                    ids_to_delete.append(values[0]) # Kolom pertama adalah ID
                    md5s_preview.append(values[1][:10] + "...") # Preview MD5
            except tk.TclError:
                self.log_db(f"Warning: Item {item_id} tidak valid atau sudah dihapus.")
                continue # Lanjut ke item berikutnya jika ada error

        if not ids_to_delete:
            self.log_db("Gagal mendapatkan ID hash terpilih yang valid.")
            return

        preview_str = "\n".join(md5s_preview)
        konfirmasi = messagebox.askyesno("Konfirmasi Hapus Hash",
                                        f"Anda yakin ingin menghapus {len(ids_to_delete)} entri hash berikut dari database?\n\n{preview_str}\n\nTindakan ini tidak bisa dibatalkan.",
                                        icon='warning')
        if not konfirmasi:
            self.log_db("Penghapusan hash dibatalkan.")
            return

        self.log_db(f"Memulai penghapusan {len(ids_to_delete)} entri...")
        sukses_count = 0
        gagal_count = 0

        # Lakukan penghapusan di thread terpisah agar GUI tidak macet jika banyak
        threading.Thread(target=self._delete_hash_action, args=(ids_to_delete,), daemon=True).start()

    def _delete_hash_action(self, ids_to_delete):
        """Helper function to run deletion in a background thread."""
        sukses_count = 0
        gagal_count = 0
        for sig_id in ids_to_delete:
            sukses, pesan = self.scanner.delete_hash_by_id(sig_id)
            if sukses:
                self.progress_queue.put(f"DB_INFO: ID {sig_id}: {pesan}") # Kirim ke queue
                sukses_count += 1
            else:
                self.progress_queue.put(f"DB_ERROR: ID {sig_id}: {pesan}") # Kirim ke queue
                gagal_count += 1

        self.progress_queue.put(f"DB_INFO: Proses penghapusan selesai: {sukses_count} berhasil, {gagal_count} gagal.")
        self.progress_queue.put("DB_UPDATED") # Kirim sinyal untuk refresh treeview
    # --- AKHIR FUNGSI BARU ---

    def proses_antrian(self):
        # ... (Sama seperti v2.9) ...
        try:
            while True:
                pesan = self.progress_queue.get_nowait()
                prefix_pindai = ("TOTAL_FILES:", "PROGRESS:", "TERDETEKSI:", "STATUS:", "ERROR:", "FATAL_ERROR:", "ERROR_HITUNG:", "ERROR_PINDAI:", "ERROR_HASH:")
                prefix_db = ("DB_SUKSES:", "DB_INFO:", "DB_ERROR:")
                if pesan.startswith(prefix_pindai):
                    self.log(pesan)
                    if pesan.startswith("TOTAL_FILES:"): total = int(pesan.split(":")[1]); self.progressbar.config(maximum=total if total > 0 else 100)
                    elif pesan.startswith("PROGRESS:"): self.progressbar.step(int(pesan.split(":")[1]))
                    elif pesan.startswith("TERDETEKSI:"):
                         if hasattr(self, 'listbox_terinfeksi'): self.listbox_terinfeksi.insert(END, pesan.replace("TERDETEKSI: ", ""))
                elif pesan.startswith("SELESAI:"): self.selesaikan_pemindaian(pesan)
                elif pesan.startswith("DIBATALKAN:"): self.selesaikan_pemindaian(pesan)
                elif pesan.startswith(prefix_db): self.log_db(pesan.split(":", 1)[1].strip())
                elif pesan == "DB_SELESAI_TAMBAH_VIRUS":
                     if hasattr(self, 'tombol_tambah_virus'): self.tombol_tambah_virus.config(state=NORMAL)
                elif pesan == "DB_UPDATED": self.muat_tampilan_database()
                else: self.log(f"Pesan Antrian Tdk Dikenal: {pesan}")
        except queue.Empty: pass
        finally: self.after(100, self.proses_antrian)

    def muat_tampilan_database(self):
        # ... (Sama seperti v2.9) ...
        if not hasattr(self, 'db_treeview'): self.after(200, self.muat_tampilan_database); return
        for item in self.db_treeview.get_children(): self.db_treeview.delete(item)
        rows, error_msg = self.scanner.get_all_signatures()
        if error_msg: self.log_db(f"ERROR: Gagal memuat data DB: {error_msg}"); self.db_treeview.insert('', END, values=("Error", error_msg, "", ""))
        elif rows:
            for row in rows: self.db_treeview.insert('', END, values=row)
            self.log_db(f"Tampilan database diperbarui ({len(rows)} entri).")
        else: self.log_db("Database tanda tangan virus masih kosong."); self.db_treeview.insert('', END, values=("Info", "Database Kosong", "", ""))

    def muat_daftar_karantina(self):
        # ... (Sama seperti v2.9) ...
        if not hasattr(self, 'listbox_karantina'): self.after(200, self.muat_daftar_karantina); return
        try:
            self.listbox_karantina.delete(0, END)
            if not os.path.exists(KARANTINA_DIR): os.makedirs(KARANTINA_DIR); self.log(f"Folder karantina '{KARANTINA_DIR}' dibuat."); self.listbox_karantina.insert(END, "(Karantina kosong)"); return
            files = os.listdir(KARANTINA_DIR)
            if not files: self.listbox_karantina.insert(END, "(Karantina kosong)"); self.log("Folder karantina kosong.")
            else:
                for f in sorted(files): self.listbox_karantina.insert(END, f)
                self.log(f"Berhasil memuat {len(files)} file dari karantina.")
        except Exception as e: self.log(f"ERROR: Gagal memuat daftar karantina: {e}"); self.listbox_karantina.insert(END, f"Error: {e}")

    def pulihkan_file_terpilih(self):
        # ... (Sama seperti v2.9) ...
        indeks_terpilih = self.listbox_karantina.curselection();
        if not indeks_terpilih: messagebox.showwarning("Tidak Ada Pilihan", "Pilih file dari daftar karantina untuk dipulihkan."); return
        folder_tujuan = filedialog.askdirectory(title="Pilih folder tujuan untuk memulihkan file");
        if not folder_tujuan: return
        sukses = 0; gagal = 0
        for indeks in sorted(indeks_terpilih, reverse=True):
            try:
                nama_file = self.listbox_karantina.get(indeks); path_sumber = os.path.join(KARANTINA_DIR, nama_file); path_tujuan = os.path.join(folder_tujuan, nama_file)
                if os.path.exists(path_tujuan):
                    konfirmasi_timpa = messagebox.askyesno("Konfirmasi Timpa", f"File '{nama_file}' sudah ada di tujuan.\nTimpa file tersebut?");
                    if not konfirmasi_timpa: self.log(f"INFO PULIH: Pemulihan '{nama_file}' dibatalkan."); continue
                shutil.move(path_sumber, path_tujuan); self.log(f"BERHASIL PULIH: File '{nama_file}' dipulihkan ke '{folder_tujuan}'."); self.listbox_karantina.delete(indeks); sukses += 1
            except Exception as e: self.log(f"GAGAL PULIH: Gagal memulihkan '{nama_file}'. Error: {e}"); gagal += 1
        self.log(f"Pemulihan selesai: {sukses} berhasil, {gagal} gagal.")

    def hapus_permanen_terpilih(self):
        # ... (Sama seperti v2.9) ...
        indeks_terpilih = self.listbox_karantina.curselection();
        if not indeks_terpilih: messagebox.showwarning("Tidak Ada Pilihan", "Pilih file dari daftar karantina untuk dihapus."); return
        konfirmasi = messagebox.askyesno("Konfirmasi Hapus Permanen", f"Anda yakin ingin menghapus {len(indeks_terpilih)} file ini secara permanen?\n\nTindakan ini tidak bisa dibatalkan.", icon='warning');
        if not konfirmasi: return
        sukses = 0; gagal = 0
        for indeks in sorted(indeks_terpilih, reverse=True):
            try:
                nama_file = self.listbox_karantina.get(indeks); path_file = os.path.join(KARANTINA_DIR, nama_file); os.remove(path_file)
                self.log(f"BERHASIL HAPUS: File '{nama_file}' telah dihapus permanen."); self.listbox_karantina.delete(indeks); sukses += 1
            except Exception as e: self.log(f"GAGAL HAPUS: Gagal menghapus '{nama_file}'. Error: {e}"); gagal += 1
        self.log(f"Penghapusan selesai: {sukses} berhasil, {gagal} gagal.")

    def karantina_file_terpilih(self):
        # ... (Sama seperti v2.9) ...
        indeks_terpilih = self.listbox_terinfeksi.curselection();
        if not indeks_terpilih: messagebox.showwarning("Tidak Ada Pilihan", "Pilih file dari daftar infeksi terlebih dahulu."); return
        if not self.pastikan_folder_karantina(): return
        sukses = 0; gagal = 0; file_dipindah = []
        for indeks in sorted(indeks_terpilih, reverse=True):
            try:
                path_file_terinfeksi = self.listbox_terinfeksi.get(indeks); nama_file_asli = os.path.basename(path_file_terinfeksi); path_tujuan = os.path.join(KARANTINA_DIR, nama_file_asli)
                counter = 1; nama_tanpa_ext, ext = os.path.splitext(nama_file_asli)
                while os.path.exists(path_tujuan): nama_file_baru = f"{nama_tanpa_ext} ({counter}){ext}"; path_tujuan = os.path.join(KARANTINA_DIR, nama_file_baru); counter += 1
                nama_file_final = os.path.basename(path_tujuan)
                shutil.move(path_file_terinfeksi, path_tujuan); log_msg = f"BERHASIL (Terpilih): File '{nama_file_asli}' telah dikarantina"; log_msg += f" sebagai '{nama_file_final}'." if nama_file_final != nama_file_asli else "."; self.log(log_msg)
                file_dipindah.append(indeks); sukses += 1
            except Exception as e: self.log(f"GAGAL (Terpilih): Gagal karantina '{path_file_terinfeksi}'. Error: {e}"); gagal += 1
        for indeks in sorted(file_dipindah, reverse=True):
            if hasattr(self, 'listbox_terinfeksi'): self.listbox_terinfeksi.delete(indeks)
        self.log(f"Karantina terpilih selesai: {sukses} berhasil, {gagal} gagal.");
        if sukses > 0: self.muat_daftar_karantina()

    def karantina_semua(self):
        # ... (Sama seperti v2.9) ...
        daftar_path = list(self.listbox_terinfeksi.get(0, END));
        if not daftar_path: messagebox.showinfo("Listbox Kosong", "Tidak ada file terdeteksi untuk dikarantina."); return
        jumlah = len(daftar_path); konfirmasi = messagebox.askyesno("Konfirmasi Karantina Semua", f"Anda yakin ingin mengarantina semua {jumlah} file yang terdeteksi?")
        if not konfirmasi: return
        if not self.pastikan_folder_karantina(): return
        self.log(f"Memulai karantina total {jumlah} file..."); sukses = 0; gagal = 0; file_dipindah = []
        for indeks in range(jumlah - 1, -1, -1):
            try:
                path_file_terinfeksi = daftar_path[indeks]; nama_file_asli = os.path.basename(path_file_terinfeksi); path_tujuan = os.path.join(KARANTINA_DIR, nama_file_asli)
                counter = 1; nama_tanpa_ext, ext = os.path.splitext(nama_file_asli)
                while os.path.exists(path_tujuan): nama_file_baru = f"{nama_tanpa_ext} ({counter}){ext}"; path_tujuan = os.path.join(KARANTINA_DIR, nama_file_baru); counter += 1
                nama_file_final = os.path.basename(path_tujuan)
                shutil.move(path_file_terinfeksi, path_tujuan); log_msg = f"BERHASIL (Semua): File '{nama_file_asli}' telah dikarantina"; log_msg += f" sebagai '{nama_file_final}'." if nama_file_final != nama_file_asli else "."; self.log(log_msg)
                file_dipindah.append(indeks); sukses += 1
            except Exception as e: self.log(f"GAGAL (Semua): Gagal karantina '{path_file_terinfeksi}'. Error: {e}"); gagal += 1
        for indeks in sorted(file_dipindah, reverse=True):
             if hasattr(self, 'listbox_terinfeksi'): self.listbox_terinfeksi.delete(indeks)
        self.log(f"Karantina total selesai: {sukses} berhasil, {gagal} gagal.")
        if sukses > 0: self.muat_daftar_karantina()

    def pastikan_folder_karantina(self):
        # ... (Sama seperti v2.9) ...
        try:
            if not os.path.exists(KARANTINA_DIR): os.makedirs(KARANTINA_DIR); self.log(f"Folder '{KARANTINA_DIR}' dibuat.")
            return True
        except Exception as e: messagebox.showerror("Error Folder", f"Gagal membuat folder karantina: {e}"); return False

# ======================================================================
# --- Titik Masuk Program ---
# ======================================================================
if __name__ == "__main__":
    # Gunakan fungsi is_admin yang diimpor
    if os.name == 'nt':
        if not is_admin():
            print("Meminta hak akses Administrator...")
            try:
                result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{__file__}"', None, 1)
                if result <= 32: print(f"Gagal meminta hak akses (Error Code: {result}). Jalankan manual sebagai Admin.")
            except Exception as e: print(f"Gagal meminta hak akses: {e}. Jalankan manual sebagai Admin.")
            sys.exit(0)
        app = AntivirusApp()
        app.mainloop()
    else:
        print("Menjalankan di OS non-Windows. Hak akses root mungkin diperlukan untuk pemindaian penuh.")
        app = AntivirusApp()
        app.mainloop()