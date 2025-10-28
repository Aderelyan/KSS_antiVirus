# File: utils.py

import ctypes
import sys
import os # Diperlukan jika ingin menambah cek OS lain

def is_admin():
    """Memeriksa apakah skrip sedang berjalan dengan hak akses Admin di Windows."""
    # Karena kita hanya menargetkan Windows, kita bisa sederhanakan
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        # Untuk OS lain, anggap bukan admin (atau tambahkan cek `os.geteuid() == 0` jika perlu)
        return False