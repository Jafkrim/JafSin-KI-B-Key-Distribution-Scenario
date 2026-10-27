# client active

import os
import socket
import threading
from aes import encrypt_block, decrypt_block, key_expansion
from utils import pad, unpad

KDC_HOST = '127.0.0.1'
KDC_PORT = 5000
BOB_PORT = 6000
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

def recv_until_close(sock: socket.socket) -> bytes:
    # KDC mengirim respons lalu menutup koneksi, jadi data dibaca sampai EOF.
    buf = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)

def send_framed(sock: socket.socket, data: bytes) -> None:
    # Panjang pesan dijadikan header 4 bytes karena Alice dan Bob bertukar pesan
    # dua arah pada satu koneksi, sehingga batas pesan tidak bisa ditandai EOF.
    sock.sendall(len(data).to_bytes(4, 'big') + data)

def recv_framed(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 4)
    if header is None:
        raise ConnectionError("Koneksi ditutup sebelum header pesan diterima")
    return recv_exact(sock, int.from_bytes(header, 'big')) or b''

def receive_loop(sock: socket.socket, ks: bytes) -> None:
    # Berjalan di thread terpisah agar Alice bisa menerima pesan kapan saja,
    # termasuk saat dirinya sedang menunggu input.
    while True:
        try:
            cipher = recv_framed(sock)
        except (ConnectionError, OSError):
            # Koneksi ditutup peer, atau socket lokal ditutup saat kita sendiri keluar.
            print("\n[!] Bob menutup koneksi. Sesi berakhir.")
            os._exit(0)
        message = decrypt_message(cipher, ks).decode('utf-8')
        print(f"\n[Bob] {message}")
        print(f"[Bob] Ciphertext [Hex] : {cipher.hex()}")
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
        print(f"[Kamu -> Bob] {message}")
        print(f"[Kamu -> Bob] Ciphertext [Hex] : {cipher.hex()}")

    print("[*] Menutup sesi dengan Bob.")
    sock.close()

def main():
    print("========================================")
    print("           ALICE (CLIENT ACTIVE)        ")
    print("========================================")

    ka_input = input("[?] Masukkan Master Key Alice (Ka) [Misal: alice_rahasia_12]: ")
    ka = derive_key(ka_input)

    id_a = input("[?] ID Alice [Enter untuk: alice]: ").strip() or "alice"
    id_b = input("[?] ID Bob [Enter untuk: bob]: ").strip() or "bob"
    kdc_host = input("[?] Alamat KDC [Enter untuk: 127.0.0.1]: ").strip() or KDC_HOST
    bob_host = input("[?] Alamat Bob [Enter untuk: 127.0.0.1]: ").strip() or KDC_HOST

    # Nonce N1 dipakai KDC untuk membuktikan bahwa responsnya masih segar.
    n1 = os.urandom(8).hex()
    print(f"[*] Nonce N1 (hex) : {n1}")

    try:
        # Langkah 1: meminta session key ke KDC dalam bentuk plaintext (IDA || IDB || N1).
        request = f"{id_a}||{id_b}||{n1}".encode('ascii')
        kdc_sock = socket.create_connection((kdc_host, KDC_PORT))
        kdc_sock.sendall(request)
        print(f"[+] Request terkirim ke KDC : {request.decode('ascii')}")

        # Menerima respons terenkripsi dari KDC.
        response = recv_until_close(kdc_sock)
        kdc_sock.close()

        # Langkah 2: membuka respons dengan kunci master Ka.
        response_plain = decrypt_message(response, ka)

        # Layout respons: Ks(16 bytes) || IDB || N1 || ticket_B.
        # Ks dipotong secara posisional agar aman dari kebetulan berisi separator.
        ks = response_plain[:BLOCK_SIZE]
        res_id_b, res_n1, ticket_b = response_plain[BLOCK_SIZE + len(SEPARATOR):].split(SEPARATOR, 2)

        print(f"[*] Session Key (Ks)     [Hex] : {ks.hex()}")
        print(f"[*] Ticket Bob (E_Kb)    [Hex] : {ticket_b.hex()}")

        # Memverifikasi nonce dan identitas dari KDC untuk mencegah replay.
        if res_n1 != n1.encode('ascii') or res_id_b != id_b.encode('ascii'):
            print("[-] Verifikasi respons KDC gagal, sesi dihentikan.")
            return
        print("[+] Respons KDC tervalidasi (N1 dan IDB cocok).")

        # Langkah 3: mengirim ticket ke Bob. Hanya Bob yang bisa membukanya dengan Kb.
        bob_sock = socket.create_connection((bob_host, BOB_PORT))
        send_framed(bob_sock, ticket_b)
        print("[+] Ticket diteruskan ke Bob.")

        # Langkah 4: menerima tantangan E_Ks(N2) dari Bob.
        challenge = recv_framed(bob_sock)
        n2 = decrypt_message(challenge, ks).decode('ascii')
        print(f"[*] Tantangan N2 dari Bob : {n2}")

        # Langkah 5: membalas E_Ks(N2 - 1) sebagai bukti Alice memegang Ks.
        send_framed(bob_sock, encrypt_message(str(int(n2) - 1).encode('ascii'), ks))
        print("[+] Balasan E_Ks(N2-1) terkirim ke Bob.")
        print("[+] Bob terautentikasi, sesi aman dengan Ks sudah terbentuk.")

        # Langkah 6: masuk ke pertukaran pesan dua arah memakai session key Ks.
        chat_loop(bob_sock, ks)

    except KeyboardInterrupt:
        print("\n[*] Alice dihentikan oleh user.")
    except Exception as e:
        print(f"\n[-] Terjadi error pada Alice: {e}")

if __name__ == "__main__":
    main()