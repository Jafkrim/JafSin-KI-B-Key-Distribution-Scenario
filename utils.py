# helper

# ===============
# KONVERSI FORMAT
# ===============

def ascii_to_bytes(text: str) -> bytes:
    return text.encode('ascii')

def bytes_to_ascii(data: bytes) -> str:
    return data.decode('ascii')

def bytes_to_hex(data: bytes) -> str:
    return data.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    hex_str = hex_str.strip()
    if hex_str.startswith(('0x', '0X')):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)

# =======
# PADDING
# =======

def pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Data cannot be empty")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# =============================
# OPERASI BITWISE DAN DEBUGGING
# =============================

def xor_bytes(b1: bytes, b2: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(b1, b2))

def print_state(state: list[list[int]], label: str = ""):
    if label:
        print(f"[{label}]")
    for row in state:
        print(" ".join(f"{val:02x}" for val in row))

def print_hex_block(data: bytes, label: str = ""):
    if label:
        print(f"[{label}]")
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        print(" ".join(f"{b:02x}" for b in chunk))