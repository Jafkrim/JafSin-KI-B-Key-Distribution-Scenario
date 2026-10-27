# server

import socket
import os
from aes import encrypt_block, key_expansion
from utils import pad

def encrypt_message(plaintext_bytes: bytes, key_bytes: bytes) -> bytes:
    # Membangkitkan round keys dari kunci master.
    round_keys = key_expansion(key_bytes)

    # Menambahkan padding ke plaintext agar panjangnya menjadi kelipatan 16 bytes.
    padded_data = pad(plaintext_bytes, 16)

    # Membuat bytearray untuk menyimpan ciphertext.
    ciphertext = bytearray()

    # Memotong data menjadi blok 16 bytes dan mengenkripsinya satu per satu.
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i+16]
        encrypted = encrypt_block(block, round_keys)
        ciphertext.extend(encrypted)                    # Menggabungkan blok terenkripsi ke ciphertext.
        
    return bytes(ciphertext)

def main():
    print("========================================")
    print("          KDC SERVER ACTIVE             ")
    print("========================================")

    ka_input = input("[?] Masukkan Master Key Alice (Ka) [Misal: alice_rahasia_12]: ")
    kb_input = input("[?] Masukkan Master Key Bob (Kb) [Misal: bob_rahasia_1234]: ")

    # Memastikan kunci master memiliki panjang 16 bytes (128 bit) dengan padding atau pemotongan.
    ka = ka_input.encode('ascii').ljust(16, b'\0')[:16]
    kb = kb_input.encode('ascii').ljust(16, b'\0')[:16]
    
    HOST = '0.0.0.0'
    PORT = 5000
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    
    print(f"\n[*] KDC standby di Port {PORT}")
    print("[*] Menunggu request koneksi dari Alice...")
    
    try:
        while True:
            conn, addr = server_sock.accept()
            print(f"\n[+] Koneksi diterima dari {addr[0]}:{addr[1]}")

            # Menerima data request dari Alice.
            req_data = conn.recv(1024)
            if not req_data:
                conn.close()
                continue

            # Mengubah data request menjadi string untuk ditampilkan.
            req_str = req_data.decode('ascii')
            print(f"[*] Data masuk dari Alice (Plaintext) : {req_str}")
            
            parts = req_str.split('||')
            if len(parts) < 3:
                print("[-] Format request tidak valid, koneksi ditutup.")
                conn.close()
                continue
                
            id_a, id_b, n1 = parts[0], parts[1], parts[2]

            # Membuat session key Ks secara acak (16 bytes).
            ks = os.urandom(16)
            print(f"[*] Session Key (Ks) digenerate [Hex] : {ks.hex()}")

            # Membuat ticket untuk Bob berisi session key Ks dan ID Alice,
            # kemudian mengenkripsinya dengan kunci master Bob (Kb).
            ticket_plain = ks + b'||' + id_a.encode('ascii')
            ticket_b_encrypted = encrypt_message(ticket_plain, kb)
            print(f"[*] Ticket Bob dibuat           [Hex] : {ticket_b_encrypted.hex()}")

            # Membungkus respons untuk Alice, termasuk session key Ks, ID Bob, nonce N1, dan ticket terenkripsi untuk Bob.
            separator = b'||'
            response_plain = (
                ks + separator + 
                id_b.encode('ascii') + separator + 
                n1.encode('ascii') + separator + 
                ticket_b_encrypted
            )

            # Membungkus seluruh respons dan mengenkripsinya dengan kunci master Ka.
            response_encrypted = encrypt_message(response_plain, ka)
            print(f"[*] Respon Alice dibungkus      [Hex] : {response_encrypted.hex()}")

            conn.sendall(response_encrypted)
            print("[+] Respon terenkripsi berhasil dikirim ke Alice!")

            # Menutup koneksi supaya Alice dapat berkomunikasi dengan Bob menggunakan session key Ks dan ticket yang diterima.
            conn.close()
            
    except KeyboardInterrupt:
        print("\n[*] Server KDC dimatikan oleh user.")
    except Exception as e:
        print(f"\n[-] Terjadi error pada KDC: {e}")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()