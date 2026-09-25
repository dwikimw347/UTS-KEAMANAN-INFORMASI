import base64
import streamlit as st

from crypto_core import (
    AES_256_GCM,
    CHACHA20_POLY1305,
    DecryptionFailed,
    InvalidEncryptedData,
    encrypt_bytes,
    decrypt_bytes,
    encrypt_text,
    decrypt_text,
)

st.set_page_config(
    page_title="Aplikasi Kriptografi",
    page_icon="",
    layout="wide",
)

st.title("Aplikasi Kriptografi")
st.caption("Enkripsi dan dekripsi teks atau berkas menggunakan AES-256-GCM / ChaCha20-Poly1305.")

# =========================
# Sidebar
# =========================
with st.sidebar:
    st.header("Pengaturan")

    mode = st.radio(
        "Pilih operasi",
        ["Enkripsi", "Dekripsi"],
    )

    algorithm = st.selectbox(
        "Pilih algoritma",
        [AES_256_GCM, CHACHA20_POLY1305],
    )

    password = st.text_input(
        "Kata sandi",
        type="password",
        help="Kata sandi digunakan untuk menurunkan kunci enkripsi.",
    )

    if mode == "Enkripsi":
        st.info("Untuk enkripsi, hasil berkas akan menggunakan format .kripto.")
    else:
        st.info("Untuk dekripsi berkas, unggah berkas hasil enkripsi dengan ekstensi .kripto.")


# =========================
# Pilih jenis input
# =========================
input_type = st.radio(
    "Jenis input",
    ["Teks", "Berkas"],
    horizontal=True,
)

st.divider()

# =========================
# ENKRIPSI
# =========================
if mode == "Enkripsi":
    if input_type == "Teks":
        st.subheader("Enkripsi Teks")

        text_input = st.text_area(
            "Masukkan teks",
            height=200,
            placeholder="Contoh: Halo dunia!",
        )

        if st.button("Enkripsi Teks", type="primary", use_container_width=True):
            if not password:
                st.error("Kata sandi wajib diisi.")
            elif not text_input:
                st.error("Teks belum diisi.")
            else:
                try:
                    result = encrypt_text(text_input, password, algorithm)

                    st.success("Teks berhasil dienkripsi.")

                    st.subheader("Hasil Base64")
                    st.code(result, language="text")

                    # Text area dapat dipilih dan disalin dengan Ctrl+C.
                    st.text_area(
                        "Base64 (siap disalin)",
                        value=result,
                        height=180,
                    )

                    st.download_button(
                        "Unduh hasil Base64",
                        data=result.encode("utf-8"),
                        file_name="hasil_enkripsi_base64.txt",
                        mime="text/plain",
                        use_container_width=True,
                    )

                except Exception as exc:
                    st.error(f"Enkripsi gagal: {exc}")

    else:
        st.subheader("Enkripsi Berkas")

        uploaded_file = st.file_uploader(
            "Unggah berkas yang ingin dienkripsi",
            type=None,
        )

        if uploaded_file is not None:
            st.write(f"**Nama:** {uploaded_file.name}")
            st.write(f"**Ukuran:** {uploaded_file.size:,} byte")

        if st.button("Enkripsi Berkas", type="primary", use_container_width=True):
            if not password:
                st.error("Kata sandi wajib diisi.")
            elif uploaded_file is None:
                st.error("Berkas belum diunggah.")
            else:
                try:
                    original_data = uploaded_file.getvalue()
                    encrypted_data = encrypt_bytes(
                        original_data,
                        password,
                        algorithm,
                    )

                    output_name = f"{uploaded_file.name}.kripto"

                    st.success("Berkas berhasil dienkripsi.")

                    st.download_button(
                        "Unduh berkas terenkripsi",
                        data=encrypted_data,
                        file_name=output_name,
                        mime="application/octet-stream",
                        use_container_width=True,
                    )

                    st.subheader("Representasi Base64")
                    encoded = base64.b64encode(encrypted_data).decode("ascii")

                    st.text_area(
                        "Base64 (siap disalin)",
                        value=encoded,
                        height=180,
                    )

                except Exception as exc:
                    st.error(f"Enkripsi gagal: {exc}")


# =========================
# DEKRIPSI
# =========================
else:
    if input_type == "Teks":
        st.subheader("Dekripsi Teks")

        encrypted_text = st.text_area(
            "Masukkan Base64 hasil enkripsi",
            height=200,
            placeholder="Tempel Base64 di sini...",
        )

        if st.button("Dekripsi Teks", type="primary", use_container_width=True):
            if not password:
                st.error("Kata sandi wajib diisi.")
            elif not encrypted_text.strip():
                st.error("Base64 belum diisi.")
            else:
                try:
                    original_text = decrypt_text(
                        encrypted_text.strip(),
                        password,
                    )

                    st.success("Teks berhasil didekripsi.")

                    st.subheader("Hasil Dekripsi")
                    st.text_area(
                        "Teks asli",
                        value=original_text,
                        height=200,
                    )

                    st.download_button(
                        "Unduh hasil dekripsi",
                        data=original_text.encode("utf-8"),
                        file_name="hasil_dekripsi.txt",
                        mime="text/plain",
                        use_container_width=True,
                    )

                except (DecryptionFailed, InvalidEncryptedData) as exc:
                    st.error(f"Dekripsi gagal: {exc}")
                except UnicodeDecodeError:
                    st.error("Data berhasil didekripsi tetapi bukan teks UTF-8 yang valid.")
                except Exception as exc:
                    st.error(f"Dekripsi gagal: {exc}")

    else:
        st.subheader("Dekripsi Berkas")

        uploaded_file = st.file_uploader(
            "Unggah berkas .kripto",
            type=["kripto"],
        )

        if uploaded_file is not None:
            st.write(f"**Nama:** {uploaded_file.name}")
            st.write(f"**Ukuran:** {uploaded_file.size:,} byte")

        if st.button("Dekripsi Berkas", type="primary", use_container_width=True):
            if not password:
                st.error("Kata sandi wajib diisi.")
            elif uploaded_file is None:
                st.error("Berkas .kripto belum diunggah.")
            else:
                try:
                    encrypted_data = uploaded_file.getvalue()
                    decrypted_data = decrypt_bytes(
                        encrypted_data,
                        password,
                    )

                    if uploaded_file.name.lower().endswith(".kripto"):
                        output_name = uploaded_file.name[:-7]
                    else:
                        output_name = f"{uploaded_file.name}.decrypted"

                    st.success("Berkas berhasil didekripsi.")

                    st.download_button(
                        "Unduh berkas hasil dekripsi",
                        data=decrypted_data,
                        file_name=output_name,
                        mime="application/octet-stream",
                        use_container_width=True,
                    )

                except (DecryptionFailed, InvalidEncryptedData) as exc:
                    st.error(f"Dekripsi gagal: {exc}")
                except Exception as exc:
                    st.error(f"Dekripsi gagal: {exc}")


st.divider()
st.caption("Catatan: aplikasi ini memproses seluruh isi berkas di memori dan sesuai modul ditujukan untuk ukuran uji hingga 10 MB.")
