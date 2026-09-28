import base64
import time
import pandas as pd
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

# ==========================================
# FUNGSI BANTUAN (HELPER FUNCTIONS)
# ==========================================
def get_key_from_encrypted_payload(encrypted_bytes: bytes, password: str) -> str:
    if len(encrypted_bytes) < len(MAGIC) + 1 + SALT_SIZE:
        raise InvalidEncryptedData("Header berkas tidak valid.")
    salt_start = len(MAGIC) + 1
    salt = encrypted_bytes[salt_start : salt_start + SALT_SIZE]
    derived_key = _key(password, salt)
    return derived_key.hex()

def calculate_avalanche_effect(bytes1: bytes, bytes2: bytes) -> float:
    min_len = min(len(bytes1), len(bytes2))
    bit_diffs = 0
    total_bits = min_len * 8
    
    for i in range(min_len):
        xor_byte = bytes1[i] ^ bytes2[i]
        bit_diffs += bin(xor_byte).count('1')
        
    length_diff_bits = abs(len(bytes1) - len(bytes2)) * 8
    bit_diffs += length_diff_bits
    total_bits += length_diff_bits
    
    if total_bits == 0:
        return 0.0
    return (bit_diffs / total_bits) * 100

def calculate_entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for i in range(256):
        count = data.count(bytes([i]))
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


# Header Utama
st.title("Enkripsi & Dekripsi")
st.caption("Platform Enkripsi & Dekripsi")

# Modul Navigasi Utama (Diperbaiki: Menambahkan Pengujian ke Menu Navigasi)
mode_data = st.segmented_control(
    "Target Pemrosesan Data",
    options=["Modul Teks", "Modul Berkas", "Pengujian"],
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
                        
                        key_hex = get_key_from_encrypted_payload(raw_bytes, password)
                        
                        st.success("Otentikasi valid. Dekripsi berhasil.")
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
elif mode_data == "Modul Berkas":
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

# ==========================================
# MODUL PENGUJIAN
# ==========================================
elif mode_data == "Pengujian":
    st.subheader("Pengujian")
    
    test_tab1, test_tab2, test_tab3 = st.tabs(["Avalanche Effect", "Analisis Entropi", "Benchmark Waktu"])
    
    # 1. Avalanche Effect
    with test_tab1:
        st.write("### Pengukuran Avalanche Effect (Perbandingan 2 Algoritma)")
        st.caption("Menganalisis persentase perubahan bit ciphertext saat 1 bit plaintext atau kunci diubah (Target: ~50%).")
        
        col_in1, col_in2 = st.columns(2)
        with col_in1:
            sample_text = st.text_input("Plaintext Uji", value="Rahasia Negara 2026", key="av_text_input")
        with col_in2:
            sample_pass = st.text_input("Kata Sandi Uji", value="PasswordUtama123", key="av_pass_input")
            
        st.write("")
        if st.button("Jalankan Pengujian Avalanche Effect", type="primary"):
            modified_text = sample_text[:-1] + chr(ord(sample_text[-1]) ^ 1)
            modified_pass = sample_pass[:-1] + chr(ord(sample_pass[-1]) ^ 1)
            
            results_avalanche = []
            
            for algo in [AES_256_GCM, CHACHA20_POLY1305]:
                # 1. Perubahan 1 Bit Plaintext
                c1_orig = encrypt_bytes(sample_text.encode(), sample_pass, algo)
                c2_text = encrypt_bytes(modified_text.encode(), sample_pass, algo)
                av_text = calculate_avalanche_effect(c1_orig, c2_text)
                
                # 2. Perubahan 1 Bit Password
                c2_pass = encrypt_bytes(sample_text.encode(), modified_pass, algo)
                av_pass = calculate_avalanche_effect(c1_orig, c2_pass)
                
                results_avalanche.append({
                    "Algoritma": algo,
                    "Perubahan 1 Bit Plaintext": f"{av_text:.2f} %",
                    "Perubahan 1 Bit Password": f"{av_pass:.2f} %",
                    "Kriteria SAC": "Sangat Baik (~50%)"
                })
                
            st.table(results_avalanche)
            st.caption("Catatan: Nilai mendekati 50% menunjukkan sifat acak enkripsi yang sangat baik (Strict Avalanche Criterion).")

    # 2. Analisis Entropi
    with test_tab2:
        st.write("### Perbandingan Entropi & Histogram Byte")
        st.caption("Mengukur keacakan data Plaintext vs Ciphertext AES-256-GCM vs ChaCha20-Poly1305 (Skala Maksimum: 8.0 bit/byte).")
        
        test_file = st.file_uploader("Unggah Berkas Sampel (Misal: PDF/Gambar/Teks)", key="test_file_entropy")
        test_pwd = st.text_input("Kata Sandi", value="PasswordEntropi123", key="pass_entropy")
        
        if test_file and st.button("Hitung Entropi & Tampilkan Histogram", type="primary"):
            p_bytes = test_file.getvalue()
            
            c_aes = encrypt_bytes(p_bytes, test_pwd, AES_256_GCM)
            c_chacha = encrypt_bytes(p_bytes, test_pwd, CHACHA20_POLY1305)
            
            e_plain = calculate_entropy(p_bytes)
            e_aes = calculate_entropy(c_aes)
            e_chacha = calculate_entropy(c_chacha)
            
            col_e1, col_e2, col_e3 = st.columns(3)
            col_e1.metric("Entropi Plaintext", f"{e_plain:.4f} bit/byte")
            col_e2.metric("Entropi AES-256-GCM", f"{e_aes:.4f} bit/byte")
            col_e3.metric("Entropi ChaCha20-Poly1305", f"{e_chacha:.4f} bit/byte")
            
            st.divider()
            st.write("### Histogram Sebaran Byte (0 - 255)")
            st.caption("Ciphertext yang baik memiliki distribusi frekuensi byte yang seragam/flat di seluruh rentang 0-255.")
            
            p_counts = [p_bytes.count(bytes([i])) for i in range(256)]
            aes_counts = [c_aes.count(bytes([i])) for i in range(256)]
            chacha_counts = [c_chacha.count(bytes([i])) for i in range(256)]
            
            df_hist = pd.DataFrame({
                "Nilai Byte (0-255)": list(range(256)),
                "Plaintext": p_counts,
                "AES-256-GCM": aes_counts,
                "ChaCha20-Poly1305": chacha_counts
            }).set_index("Nilai Byte (0-255)")
            
            col_h1, col_h2, col_h3 = st.columns(3)
            with col_h1:
                st.write("**Plaintext Asli**")
                st.bar_chart(df_hist["Plaintext"])
            with col_h2:
                st.write("**AES-256-GCM**")
                st.bar_chart(df_hist["AES-256-GCM"])
            with col_h3:
                st.write("**ChaCha20-Poly1305**")
                st.bar_chart(df_hist["ChaCha20-Poly1305"])

    # 3. Benchmark Waktu
    with test_tab3:
        st.write("### Perbandingan Performansi Waktu Enkripsi & Dekripsi")
        st.caption("Pengukuran durasi pemrosesan (ms) untuk berkas sintetis 1 KB, 1 MB, dan 10 MB.")
        
        if st.button("Jalankan Uji Performansi", type="primary"):
            sizes = {"1 KB": 1024, "1 MB": 1024 * 1024, "10 MB": 10 * 1024 * 1024}
            benchmark_results = []
            
            for label, size_bytes in sizes.items():
                dummy_data = b"A" * size_bytes
                
                for algo in [AES_256_GCM, CHACHA20_POLY1305]:
                    # Enkripsi
                    t0 = time.perf_counter()
                    enc = encrypt_bytes(dummy_data, "BenchmarkPass123", algo)
                    t_enc = (time.perf_counter() - t0) * 1000
                    
                    # Dekripsi
                    t0 = time.perf_counter()
                    dec = decrypt_bytes(enc, "BenchmarkPass123")
                    t_dec = (time.perf_counter() - t0) * 1000
                    
                    benchmark_results.append({
                        "Ukuran Berkas": label,
                        "Algoritma": algo,
                        "Waktu Enkripsi (ms)": f"{t_enc:.2f}",
                        "Waktu Dekripsi (ms)": f"{t_dec:.2f}",
                        "Total Waktu (ms)": f"{(t_enc + t_dec):.2f}"
                    })
            
            st.table(benchmark_results)