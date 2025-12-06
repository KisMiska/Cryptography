"""
ERVIN Cipher :)
E - 'Elaborate' key gen
R - Rotations
V - Variable permutations
I - Iterative
N - Non-linear mixing (XOR)
"""

def generate_round_keys(key, num_rounds):
    ERVIN = bytes([69, 82, 86, 73, 78])  # "ERVIN" in ASCII
    round_keys = []
    
    for round_num in range(num_rounds):
        round_key = bytearray(key)
        
        # Mix with ERVIN constant
        for i in range(len(round_key)):
            ervin_byte = ERVIN[i % len(ERVIN)]
            round_key[i] = (round_key[i] + ervin_byte + round_num) % 256
        
        round_keys.append(bytes(round_key))
    
    return round_keys


def rotate_byte_left(byte, positions):
    positions = positions % 8
    return ((byte << positions) | (byte >> (8 - positions))) & 0xFF


def _rotate_byte_right(byte, positions):
    positions = positions % 8
    return ((byte >> positions) | (byte << (8 - positions))) & 0xFF


def ervin_permutation(block, key, forward=True):
    result = bytearray(block)
    n = len(result)
    
    ERVIN = [69, 82, 86, 73, 78] # "ERVIN" in ASCII
    
    swaps = []
    for i in range(n - 1):
        key_byte = key[i % len(key)]
        ervin_val = ERVIN[i % len(ERVIN)]
        offset = (key_byte + ervin_val) % (n - i)
        j = i + offset
        swaps.append((i, j))
    
    if forward:
        for i, j in swaps:
            result[i], result[j] = result[j], result[i]
    else:
        for i, j in reversed(swaps):
            result[i], result[j] = result[j], result[i]
    
    return bytes(result)


def ervin_rotation_layer(block, round_key):
    ERVIN = [69, 82, 86, 73, 78] # "ERVIN" in ASCII
    result = bytearray(block)
    
    for i in range(len(result)):
        key_byte = round_key[i % len(round_key)]
        ervin_byte = ERVIN[i % len(ERVIN)]
        
        rotation = (key_byte + ervin_byte + i) % 8
        
        result[i] = rotate_byte_left(result[i], rotation)
    
    return bytes(result)


def ervin_inverse_rotation_layer(block, round_key):
    ERVIN = [69, 82, 86, 73, 78]
    result = bytearray(block)
    
    for i in range(len(result)):
        key_byte = round_key[i % len(round_key)]
        ervin_byte = ERVIN[i % len(ERVIN)]
        
        rotation = (key_byte + ervin_byte + i) % 8

        result[i] = _rotate_byte_right(result[i], rotation)
    
    return bytes(result)


def ervin_mixing_layer(block: bytes, round_key: bytes) -> bytes:
    ERVIN = [69, 82, 86, 73, 78] # "ERVIN" in ASCII
    result = bytearray(block)
    
    for i in range(len(result)):
        key_byte = round_key[i % len(round_key)]
        ervin_byte = ERVIN[i % len(ERVIN)]
        prev_byte = result[i - 1] if i > 0 else 0
        
        result[i] ^= key_byte
        result[i] ^= prev_byte
        result[i] ^= ervin_byte
    
    return bytes(result)


def ervin_inverse_mixing_layer(block: bytes, round_key: bytes) -> bytes:
    ERVIN = [69, 82, 86, 73, 78] # "ERVIN" in ASCII
    result = bytearray(block)
    
    for i in range(len(result) - 1, -1, -1):
        key_byte = round_key[i % len(round_key)]
        ervin_byte = ERVIN[i % len(ERVIN)]
        prev_byte = result[i - 1] if i > 0 else 0
        
        result[i] ^= ervin_byte
        result[i] ^= prev_byte
        result[i] ^= key_byte
    
    return bytes(result)


def ervin_block_encrypt(block, key):

    if len(key) == 0:
        raise ValueError("Key cannot be empty")
    
    rounds = 5 # lenght of ERVIN
    round_keys = generate_round_keys(key, rounds)
    
    result = block
    
    for round_num in range(rounds):
        rkey = round_keys[round_num]
        

        result = ervin_rotation_layer(result, rkey)
        result = ervin_permutation(result, rkey, forward=True)
        result = ervin_mixing_layer(result, rkey)
    
    return result

def ervin_block_decrypt(block, key):
    if len(key) == 0:
        raise ValueError("Key cannot be empty")
    
    rounds = 5 # lenght of ERVIN
    round_keys = generate_round_keys(key, 5)
    result = block
    
    for round in range(rounds - 1, -1, -1):
        rkey = round_keys[round]
        result = ervin_inverse_mixing_layer(result, rkey)
        result = ervin_permutation(result, rkey, forward=False)
        result = ervin_inverse_rotation_layer(result, rkey)
    
    return result