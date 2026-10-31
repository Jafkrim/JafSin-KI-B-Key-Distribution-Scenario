# JafSin-KI-B-Key-Distribution-Scenario

*Keamanan Informasi B - 2026*

| NRP | Nama Lengkap | 
| ----- | ----- | 
| 5025241040 | Ja'far Balyan Al Karim | 
| 5025241063 | Ahsin Khuluqil Karim | 

## Skenario Perangkat

Di dalam skenario ini, kami menggunakan 3 perangkat berbeda:

1. **Laptop Windows 11**, menjalankan `bob.py`

2. **Smartphone Android 16**, menjalankan `kdc.py`

3. **Laptop Linux Fedora**, menjalankan `alice.py`

## Prasyarat Perangkat Lunak

1. **Tailscale**, untuk Windows dan Linux

2. **Termux**, untuk Android

3. **Wireshark**, untuk Windows dan Android

## Pengaturan Tailscale

### Untuk Windows

1. Buka perangkat lunak **Tailscale**, lalu *login* dengan akun Google.

2. Setelah *login*, koneksikan perangkat dalam jaringan Tailscale.

3. Buka *admin console* untuk melihat perangkat yang nantinya terhubung.

### Untuk Android

1. Buka aplikasi **Tailscale**, lalu *login* dengan akun Google yang sama dengan akun pada perangkat Windows.

2. Setelah *login*, koneksikan perangkat dalam jaringan Tailscale.

3. *Refresh admin console* pada Windows untuk melihat apakah perangkat Android sudah terhubung dengan baik dan benar.

### Untuk Linux

1. a

2. b

3. c

## Pengaturan Termux

### Untuk Android

1. Buka aplikasi **Termux**, perbarui dependensi dengan menjalankan:

   ```bash
   pkg update && pkg upgrade -y
   pkg install python git -y
   ```

2. Berikan izin akses ke penyimpanan dengan perintah di bawah ini dan menekan tombol **Izinkan**:

   ```bash
   termux-setup-storage
   ```

3. Instal OpenSSH dengan:

   ```bash
   pkg install openssh -y
   ```

4. Buat *password* untuk komunikasi dengan:

   ```bash
   passwd
   ```

5. Cek *username* Termux dengan:

   ```bash
   whoami
   ```

6. Nyalakan server SSH dengan:

   ```bash
   sshd
   ```

### Untuk Windows

1. Buka **CMD**, lakukan koneksi SSH ke Termux dengan:

   ```cmd
   ssh username_termux@IP_TAILSCALE_HP -p 8022
   ```

2. Kloning repositori dengan:

   ```bash
   git clone https://github.com/Jafkrim/JafSin-KI-B-Key-Distribution-Scenario.git
   ```

## Pengaturan Wireshark

### Untuk Windows

1. a

2. b

### Untuk Linux

1. a

2. b

## Langkah Inisiasi Pengujian

### Untuk `bob.py`

1. Buka tab **CMD** baru, masuk ke direktori repositori.

2. Jalankan file dengan:

   ```cmd
   python bob.py
   ```

### Untuk `kdc.py`

1. Pada tab **CMD** yang sudah terhubung dengan koneksi SSH ke Termux, masuk ke direktori repositori.

2. Jalankan file dengan:

   ```bash
   python kdc.py
   ```

### Untuk `alice.py`

1. a

2. b

## Langkah Simulasi Pengujian

1. a

2. b

3. c

## Langkah Pengecekan Wireshark

1. a

2. b

3. c
