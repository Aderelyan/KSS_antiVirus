# File: scanner_logic.py

import hashlib
import os
import sqlite3
import threading # Diperlukan untuk Event di _check_hash

# --- KONFIGURASI (Bisa dipindahkan ke file config.py nanti) ---
DATABASE_FILE = "antivirus.db"

# ======================================================================
# --- KELAS LOGIKA PEMINDAI (Mesin) ---
# ======================================================================
class Scanner:
    def __init__(self, db_path=DATABASE_FILE): # Beri nilai default
        self.db_path = db_path
        self._init_db()

    def _create_connection(self):
        """Menciptakan koneksi BARU ke database. Wajib untuk tiap thread."""
        try:
            return sqlite3.connect(self.db_path, timeout=10)
        except Exception as e:
            print(f"FATAL DB ERROR: {e}")
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
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_md5 ON signatures (md5)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON signatures (sha256)")
        except Exception as e:
            print(f"Error saat inisialisasi DB: {e}")
        finally:
            conn.close()

    def _hitung_hashes(self, file_path):
        """Menghitung MD5 dan SHA256 sekaligus agar efisien."""
        md5_hash = hashlib.md5(); sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(4096):
                    md5_hash.update(chunk); sha256_hash.update(chunk)
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
        except PermissionError: return "Error: Izin Ditolak", None
        except Exception as e: return f"Error: {e}", None

    def _check_hash(self, conn, hash_md5, hash_sha256):
        """Memeriksa apakah SALAH SATU hash ada di DB."""
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM signatures WHERE md5 = ? OR sha256 = ?", (hash_md5, hash_sha256))
            return cursor.fetchone() is not None
        except sqlite3.OperationalError as e:
             if "locked" in str(e):
                  print("DB locked saat cek hash, mencoba lagi...")
                  threading.Event().wait(0.1) # Tunggu 100ms
                  try:
                      cursor.execute("SELECT 1 FROM signatures WHERE md5 = ? OR sha256 = ?", (hash_md5, hash_sha256))
                      return cursor.fetchone() is not None
                  except Exception as e2: print(f"Gagal retry cek hash: {e2}"); return False
             else: print(f"Error saat _check_hash: {e}"); return False
        except Exception as e: print(f"Error saat _check_hash: {e}"); return False

    def tambah_hash(self, hash_md5, hash_sha256):
        """Menambahkan KEDUA hash ke DB."""
        conn = self._create_connection();
        if not conn: return False, "Gagal terhubung ke DB"
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("INSERT OR IGNORE INTO signatures (md5, sha256) VALUES (?, ?)", (hash_md5.strip(), hash_sha256.strip()))
                return conn.total_changes > 0, ("Hash berhasil ditambahkan." if conn.total_changes > 0 else "Hash (MD5 atau SHA256) sudah ada di database.")
        except Exception as e: return False, f"Error SQL: {e}"
        finally: conn.close()

    def get_all_signatures(self):
        """Mengambil semua entri dari tabel signatures."""
        conn = self._create_connection();
        if not conn: return None, "Gagal terhubung ke DB"
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, md5, sha256, timestamp FROM signatures ORDER BY id DESC")
            return cursor.fetchall(), None
        except Exception as e: return None, f"Error SQL saat mengambil data: {e}"
        finally: conn.close()

    def delete_hash_by_id(self, signature_id):
        """Menghapus entri signature berdasarkan ID primary key."""
        conn = self._create_connection()
        if not conn: return False, "Gagal terhubung ke DB"
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM signatures WHERE id = ?", (signature_id,))
                # Cek apakah ada baris yang benar-benar dihapus
                if conn.total_changes > 0:
                    return True, f"Entri dengan ID {signature_id} berhasil dihapus."
                else:
                    return False, f"Tidak ditemukan entri dengan ID {signature_id}."
        except Exception as e:
            return False, f"Error SQL saat menghapus: {e}"
        finally:
            conn.close()

    def pindai_folder(self, folder_path, progress_queue, cancel_event):
        """
        Memindai folder menggunakan koneksi DB yang dibuat oleh thread ini.
        Dengan penanganan error os.walk yang lebih baik.
        """
        conn = self._create_connection()
        if not conn: progress_queue.put("FATAL_ERROR: Tidak bisa terhubung ke database."); return
        total_file = 0; total_terinfeksi = 0; file_dipindai = 0
        try:
            progress_queue.put("STATUS: Menghitung total file...")
            try:
                for root, dirs, files in os.walk(folder_path, topdown=True, onerror=None):
                    if cancel_event.is_set(): progress_queue.put("DIBATALKAN: Pemindaian dibatalkan saat menghitung."); return
                    try: total_file += len(files)
                    except PermissionError: progress_queue.put(f"ERROR_HITUNG: Izin ditolak untuk folder {root}")
                    except OSError as e: progress_queue.put(f"ERROR_HITUNG: Gagal akses {root} - {e}")
            except PermissionError: progress_queue.put(f"FATAL_ERROR: Izin ditolak untuk mengakses folder utama: {folder_path}"); return
            except Exception as e: progress_queue.put(f"FATAL_ERROR: Gagal saat menghitung file: {e}"); return

            progress_queue.put(f"TOTAL_FILES:{total_file}")
            if total_file == 0: progress_queue.put("SELESAI: Tidak ada file ditemukan atau bisa diakses."); return

            progress_queue.put(f"STATUS: Memulai pemindaian {total_file} file...")
            try:
                for root, dirs, files in os.walk(folder_path, topdown=True, onerror=None):
                    if cancel_event.is_set(): progress_queue.put("DIBATALKAN: Pemindaian dibatalkan oleh pengguna."); return
                    try:
                        for nama_file in files:
                            if cancel_event.is_set(): progress_queue.put("DIBATALKAN: Pemindaian dibatalkan oleh pengguna."); return
                            file_path_lengkap = os.path.join(root, nama_file)
                            file_dipindai += 1
                            hash_md5, hash_sha256 = self._hitung_hashes(file_path_lengkap)
                            if hash_sha256 is None: progress_queue.put(f"ERROR_HASH: {file_path_lengkap} ({hash_md5})")
                            elif self._check_hash(conn, hash_md5, hash_sha256): total_terinfeksi += 1; progress_queue.put(f"TERDETEKSI: {file_path_lengkap}")
                            progress_queue.put("PROGRESS:1")
                    except PermissionError: progress_queue.put(f"ERROR_PINDAI: Izin ditolak untuk file di {root}")
                    except OSError as e: progress_queue.put(f"ERROR_PINDAI: Gagal akses file di {root} - {e}")
            except PermissionError: progress_queue.put(f"FATAL_ERROR: Izin ditolak untuk mengakses folder utama: {folder_path}"); return
            except Exception as e: progress_queue.put(f"FATAL_ERROR: Gagal saat memindai file: {e}"); return
            progress_queue.put(f"SELESAI: Total Dipindai: {file_dipindai}, Terinfeksi: {total_terinfeksi}")
        finally:
            if conn: conn.close()