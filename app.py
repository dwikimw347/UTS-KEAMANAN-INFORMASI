import base64
import streamlit as st
from crypto_core import (
    AES_256_GCM,
    CHACHA20_POLY1305,
    MAGIC,
    SALT_SIZE,
    DecryptionFailed,
    InvalidEncryptedData,
    _key,
    decrypt_bytes,
    decrypt_text,
    encrypt_bytes,
    encrypt_text,
)

# Konfigurasi Halaman
st.set_page_config(
    page_title="Enkripsi & Dekripsi",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Style Kustom Dashboard
st.markdown(
    """
    <style>
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .block-container {
        padding-top: 2rem;
        max-width: 1200px;
    }
    [data-testid="column"] > div {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 20px;
    }
    div.stButton > button[kind="primary"] {
        background-color: #238636;
        border: 1px solid rgba(240,246,252,0.1);
        color: #ffffff;
        font-weight: 600;
    }
    div.stButton > button[kind="primary"]:hover {
        background-color: #2ea043;
    }
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    </style>
    """,
    unsafe_allow_html=True,
)

# Fungsi Bantuan untuk Ekstraksi Kunci Hex dari Payload
def get_key_from_encrypted_payload(encrypted_bytes: bytes, password: str) -> str:
    if len(encrypted_bytes) < len(MAGIC) + 1 + SALT_SIZE:
        raise InvalidEncryptedData("Header berkas tidak valid.")
    salt_start = len(MAGIC) + 1
    salt = encrypted_bytes[salt_start : salt_start + SALT_SIZE]
    derived_key = _key(password, salt)
    return derived_key.hex()

# Header Utama
st.title("Enkripsi & Dekripsi")
st.caption("Platform Enkripsi & Dekripsi")

# Modul Navigasi Utama
mode_data = st.segmented_control(
    "Target Pemrosesan Data",
    options=["Modul Teks", "Modul Berkas"],
    default="Modul Teks",
)

st.write("")

# ==========================================
# MODUL TEKS
# ==========================================
if mode_data == "Modul Teks":
    col_left, col_right = st.columns([1, 1], gap="large")

    with col_left:
        st.subheader("Input & Parameter")
        
        operation = st.radio(
            "Operasi Teks",
            ["Enkripsi Teks", "Dekripsi Teks"],
            horizontal=True,
            label_visibility="collapsed",
        )
        
        st.write("")
        
        if operation == "Enkripsi Teks":
            text_input = st.text_area(
                "Teks Asli (Plaintext)",
                placeholder="Tuliskan data sensitif atau pesan di sini...",
                height=160,
            )
            algorithm = st.selectbox("Algoritma AEAD", [AES_256_GCM, CHACHA20_POLY1305])
        else:
            text_input = st.text_area(
                "Payload Terenkripsi (Base64)",
                placeholder="Tempelkan string Base64 terenkripsi di sini...",
                height=160,
            )
            
        password = st.text_input("Kata Sandi Otorisasi", type="password")
        
        st.write("")
        submit_text = st.button("Jalankan Pemrosesan", type="primary", use_container_width=True)

    with col_right:
        st.subheader("Hasil")
        
        if submit_text:
            if not password:
                st.error("Kata sandi otorisasi wajib diisi.")
            elif not text_input:
                st.warning("Input data tidak boleh kosong.")
            else:
                if operation == "Enkripsi Teks":
                    try:
                        result_b64 = encrypt_text(text_input, password, algorithm)
                        
                        # Ekstraksi Kunci
                        raw_bytes = base64.b64decode(result_b64)
                        key_hex = get_key_from_encrypted_payload(raw_bytes, password)
                        
                        st.success("Proses enkripsi berhasil.")
                        
                        st.code(result_b64, language="text", wrap_lines=True)
                        st.download_button(
                            label="Unduh File Ciphertext (.txt)",
                            data=result_b64,
                            file_name="ciphertext.txt",
                            mime="text/plain",
                            use_container_width=True,
                        )
                    except Exception as err:
                        st.error(f"Gagal memproses data: {err}")
                else:
                    try:
                        raw_bytes = base64.b64decode(text_input.strip())
                        decrypted = decrypt_text(text_input.strip(), password)
                        
                        # Ekstraksi Kunci saat dekripsi berhasil
                        key_hex = get_key_from_encrypted_payload(raw_bytes, password)
                        
                        st.success("Otentikasi valid. Dekripsi berhasil.")
                        st.text_input("Kunci Turunan Scrypt 256-bit (HEX)", value=key_hex, help="Kunci dekripsi yang diekstrak menggunakan Salt dari paket.")
                        st.text_area("Plaintext Dipulihkan", value=decrypted, height=140)
                    except DecryptionFailed:
                        st.error("Gagal mendekripsi: Kata sandi salah atau isi data telah terubah.")
                    except InvalidEncryptedData:
                        st.error("Gagal mendekripsi: Format data Base64 tidak sesuai standar paket.")
                    except Exception as err:
                        st.error(f"Gagal memproses data: {err}")
        else:
            st.info("Hasil pemrosesan dan kunci akan ditampilkan di area ini setelah tombol dijalankan.")

# ==========================================
# MODUL BERKAS
# ==========================================
else:
    col_left, col_right = st.columns([1, 1], gap="large")

    with col_left:
        st.subheader("Manajemen Berkas")
        
        file_op = st.radio(
            "Operasi Berkas",
            ["Enkripsi Berkas", "Dekripsi Berkas"],
            horizontal=True,
            label_visibility="collapsed",
        )
        
        st.write("")
        
        if file_op == "Enkripsi Berkas":
            uploaded_file = st.file_uploader("Pilih Berkas Asli", type=None)
            algorithm = st.selectbox("Algoritma AEAD", [AES_256_GCM, CHACHA20_POLY1305], key="file_alg")
        else:
            uploaded_file = st.file_uploader("Pilih Berkas Terenkripsi (.kripto)", type=["kripto"])
            
        password = st.text_input("Kata Sandi Otorisasi", type="password", key="file_pass")
        
        st.write("")
        submit_file = st.button("Jalankan Pemrosesan Berkas", type="primary", use_container_width=True)

    with col_right:
        st.subheader("Ringkasan & Hasil")
        
        if uploaded_file:
            st.metric(label="Nama Berkas Upload", value=uploaded_file.name)
            st.metric(label="Ukuran Berkas", value=f"{uploaded_file.size / 1024:.2f} KB")
            st.divider()

        if submit_file:
            if not password:
                st.error("Kata sandi otorisasi wajib diisi.")
            elif not uploaded_file:
                st.warning("Silakan unggah berkas terlebih dahulu.")
            else:
                file_bytes = uploaded_file.getvalue()
                
                if file_op == "Enkripsi Berkas":
                    try:
                        encrypted_bytes = encrypt_bytes(file_bytes, password, algorithm)
                        key_hex = get_key_from_encrypted_payload(encrypted_bytes, password)
                        out_name = f"{uploaded_file.name}.kripto"
                        
                        st.success("Enkripsi berkas selesai.")
                        
                        st.download_button(
                            label=f"Unduh {out_name}",
                            data=encrypted_bytes,
                            file_name=out_name,
                            mime="application/octet-stream",
                            use_container_width=True,
                        )
                    except Exception as err:
                        st.error(f"Gagal memproses berkas: {err}")
                else:
                    try:
                        decrypted_bytes = decrypt_bytes(file_bytes, password)
                        key_hex = get_key_from_encrypted_payload(file_bytes, password)
                        
                        orig_name = uploaded_file.name
                        out_name = orig_name[:-7] if orig_name.endswith(".kripto") else f"restored_{orig_name}"
                        
                        st.success("Otentikasi sukses. Berkas dipulihkan.")
                        st.text_input("Kunci Turunan Scrypt 256-bit (HEX)", value=key_hex)
                        
                        st.download_button(
                            label=f"Unduh {out_name}",
                            data=decrypted_bytes,
                            file_name=out_name,
                            mime="application/octet-stream",
                            use_container_width=True,
                        )
                    except DecryptionFailed:
                        st.error("Gagal mendekripsi: Kata sandi salah atau berkas terenkripsi telah rusak/diubah.")
                    except InvalidEncryptedData:
                        st.error("Gagal mendekripsi: Format berkas bukan merupakan paket .kripto v1 yang valid.")
                    except Exception as err:
                        st.error(f"Gagal memproses berkas: {err}")
        else:
            if not uploaded_file:
                st.info("Unggah berkas di panel sebelah kiri untuk memulai pemrosesan.")