# client passive

import os
import socket
import threading
from aes import encrypt_block, decrypt_block, key_expansion
from utils import pad, unpad

HOST = '0.0.0.0'
PORT = 6000
SEPARATOR = b'||'
BLOCK_SIZE = 16
EXIT_WORDS = ("quit", "exit")

def encrypt_message(plaintext_bytes: bytes, key_bytes: bytes) -> bytes:
    # Membangkitkan round keys dari kunci master.
    round_keys = key_expansion(key_bytes)

    # Menambahkan padding ke plaintext agar panjangnya menjadi kelipatan 16 bytes.
    padded_data = pad(plaintext_bytes, BLOCK_SIZE)

    # Membuat bytearray untuk menyimpan ciphertext.
    ciphertext = bytearray()

    # Memotong data menjadi blok 16 bytes dan mengenkripsinya satu per satu.
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i+BLOCK_SIZE]
        ciphertext.extend(encrypt_block(block, round_keys))

    return bytes(ciphertext)

def decrypt_message(ciphertext_bytes: bytes, key_bytes: bytes) -> bytes:
    # Membangkitkan round keys dari kunci master.
    round_keys = key_expansion(key_bytes)

    # Membuat bytearray untuk menyimpan plaintext.
    plaintext = bytearray()

    # Mendekripsi ciphertext per blok 16 bytes.
    for i in range(0, len(ciphertext_bytes), BLOCK_SIZE):
        block = ciphertext_bytes[i:i+BLOCK_SIZE]
        plaintext.extend(decrypt_block(block, round_keys))

    # Membuang padding untuk mengembalikan plaintext asli.
    return unpad(bytes(plaintext))

def derive_key(text: str) -> bytes:
    # Menyamakan derivasi kunci dengan KDC: ASCII, padding nol, lalu potong 16 bytes.
    return text.encode('ascii').ljust(16, b'\0')[:16]

def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    # Membaca tepat n bytes; mengembalikan None bila koneksi ditutup sebelum lengkap.
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def send_framed(sock: socket.socket, data: bytes) -> None:
    # Panjang pesan dijadikan header 4 bytes karena dua sisi bertukar pesan
    # dua arah pada satu koneksi, sehingga batas pesan tidak bisa ditandai EOF.
    sock.sendall(len(data).to_bytes(4, 'big') + data)

def recv_framed(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 4)
    if header is None:
        raise ConnectionError("Koneksi ditutup sebelum header pesan diterima")
    return recv_exact(sock, int.from_bytes(header, 'big')) or b''

def receive_loop(sock: socket.socket, ks: bytes) -> None:
    # Berjalan di thread terpisah agar Bob bisa menerima pesan kapan saja,
    # termasuk saat dirinya sedang menunggu input.
    while True:
        try:
            cipher = recv_framed(sock)
        except (ConnectionError, OSError):
            # Koneksi ditutup peer, atau socket lokal ditutup saat kita sendiri keluar.
            print("\n[!] Alice menutup koneksi. Sesi berakhir.")
            os._exit(0)
        message = decrypt_message(cipher, ks).decode('utf-8')
        print(f"\n[Alice] {message}")
        print(f"[Alice] Ciphertext [Hex] : {cipher.hex()}")
        print("> ", end="", flush=True)

def chat_loop(sock: socket.socket, ks: bytes) -> None:
    threading.Thread(target=receive_loop, args=(sock, ks), daemon=True).start()
    print("[*] Sesi aktif. Ketik pesan, atau 'quit' untuk keluar.\n")

    while True:
        try:
            message = input("> ")
        except (EOFError, KeyboardInterrupt):
            break

        if message.strip().lower() in EXIT_WORDS:
            break
        if not message.strip():
            continue

        try:
            cipher = encrypt_message(message.encode('utf-8'), ks)
            send_framed(sock, cipher)
        except OSError:
            print("\n[!] Gagal mengirim, koneksi sudah tertutup.")
            break
        print(f"[Kamu -> Alice] {message}")
        print(f"[Kamu -> Alice] Ciphertext [Hex] : {cipher.hex()}")

    print("[*] Menutup sesi dengan Alice.")
    sock.close()

def main():
    print("========================================")
    print("           BOB (CLIENT PASSIVE)         ")
    print("========================================")

    kb_input = input("[?] Masukkan Master Key Bob (Kb) [Misal: bob_rahasia_1234]: ")
    kb = derive_key(kb_input)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)

    print(f"\n[*] Bob standby di Port {PORT}")
    print("[*] Menunggu koneksi dari Alice...")

    try:
        conn, addr = server_sock.accept()
        print(f"[+] Koneksi diterima dari {addr[0]}:{addr[1]}")

        # Langkah 1: menerima ticket E_Kb(Ks || IDA) dari Alice dan membukanya dengan Kb.
        ticket = recv_framed(conn)
        ticket_plain = decrypt_message(ticket, kb)

        # Layout ticket: Ks(16 bytes) || IDA. Ks dipotong secara posisional.
        ks = ticket_plain[:BLOCK_SIZE]
        id_a = ticket_plain[BLOCK_SIZE + len(SEPARATOR):].decode('ascii')

        print(f"[*] Ticket terbuka, sesi diminta oleh IDA : {id_a}")
        print(f"[*] Session Key (Ks) [Hex] : {ks.hex()}")

        # Langkah 2: mengirim tantangan E_Ks(N2) agar Alice membuktikan pemilikan Ks.
        n2 = str(int.from_bytes(os.urandom(4), 'big'))
        send_framed(conn, encrypt_message(n2.encode('ascii'), ks))
        print(f"[*] Tantangan N2 dikirim : {n2}")

        # Langkah 3: menerima E_Ks(N2-1) dan memverifikasinya.
        response = recv_framed(conn)
        n2_minus_1 = decrypt_message(response, ks).decode('ascii')
        if n2_minus_1 != str(int(n2) - 1):
            print("[-] Verifikasi N2-1 gagal, Alice tidak memegang Ks yang sah.")
            conn.close()
            return
        print("[+] Alice terautentikasi (N2-1 valid).")

        # Langkah 4: masuk ke pertukaran pesan dua arah memakai session key Ks.
        chat_loop(conn, ks)

    except KeyboardInterrupt:
        print("\n[*] Bob dihentikan oleh user.")
    except Exception as e:
        print(f"\n[-] Terjadi error pada Bob: {e}")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()