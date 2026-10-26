# helper

# ===============
# KONVERSI FORMAT
# ===============

def ascii_to_bytes(text: str) -> bytes:

def bytes_to_ascii(data: bytes) -> str:

def bytes_to_hex(data: bytes) -> str:

def hex_to_bytes(hex_str: str) -> bytes:

# =======
# PADDING
# =======

def pad(data: bytes, block_size: int = 16) -> bytes:

def unpad(data: bytes) -> bytes:

# =============================
# OPERASI BITWISE DAN DEBUGGING
# =============================

def xor_bytes(b1: bytes, b2: bytes) -> bytes:

def print_state(state: list[list[int]], label: str = ""):

def print_hex_block(data: bytes, label: str = ""):