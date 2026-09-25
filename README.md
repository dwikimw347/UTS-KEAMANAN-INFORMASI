# Modul kriptografi Topik A 

Modul Python untuk mengenkripsi dan mendekripsi teks atau berkas dengan
AES-256-GCM atau ChaCha20-Poly1305. Kunci 256-bit diturunkan dari kata sandi
memakai scrypt. Setiap proses enkripsi membuat salt dan nonce baru.

## Instalasi dan tes

Gunakan Python 3.10 atau lebih baru:

```powershell
python -m pip install -r requirements.txt
python -m unittest -v
```

## Contoh pemakaian untuk Orang 2 (Streamlit)

```python
from crypto_core import (
    AES_256_GCM, CHACHA20_POLY1305,
    DecryptionFailed, InvalidEncryptedData,
    encrypt_bytes, decrypt_bytes, encrypt_text, decrypt_text,
)

# Teks: hasil Base64 siap ditampilkan atau disalin.
encoded = encrypt_text("Halo dunia", "kata sandi pengguna", AES_256_GCM)
original_text = decrypt_text(encoded, "kata sandi pengguna")

# Berkas: uploaded_file.getvalue() dari Streamlit menghasilkan bytes.
encrypted = encrypt_bytes(b"isi berkas", "kata sandi pengguna", CHACHA20_POLY1305)
original_file = decrypt_bytes(encrypted, "kata sandi pengguna")

# Tampilkan pesan kesalahan; jangan tampilkan hasil bila verifikasi gagal.
try:
    original_file = decrypt_bytes(encrypted, "kata sandi salah")
except (DecryptionFailed, InvalidEncryptedData):
    print("Kata sandi salah atau data terenkripsi tidak valid.")
```

Untuk berkas pada disk, `encrypt_file("contoh.pdf", password)` membuat
`contoh.pdf.kripto`. Setelah berkas asli dipindahkan atau dihapus,
`decrypt_file("contoh.pdf.kripto", password)` memulihkan `contoh.pdf`.
Kedua fungsi tidak menimpa berkas yang sudah ada.

## Format `.kripto` versi 1

`KRIPTO1\0` (8 byte) + ID algoritma (1 byte) + salt (16 byte) + nonce
(12 byte) + cipherteks dan tag (16 byte di akhir). Header ikut diverifikasi
sebagai associated data. Parameter scrypt versi 1: `N=16384`, `r=8`,
`p=1`, panjang kunci 32 byte. Salt, nonce, dan ID algoritma bukan rahasia;
kata sandi serta kuncinya tidak disimpan di berkas.

Fungsi membaca seluruh berkas ke memori, sesuai ukuran uji tugas hingga
10 MB. Jika aplikasi kelak menangani berkas sangat besar, alur berkas perlu
dirancang ulang untuk pemrosesan bertahap.

Kata sandi pada contoh dan unit test hanyalah data contoh, bukan kredensial
aplikasi. Aplikasi akhir harus menerima kata sandi dari pengguna dan tidak
menyimpannya di kode sumber atau repositori.
