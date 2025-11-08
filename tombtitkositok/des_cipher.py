from Crypto.Cipher import DES as CryptoDES

def des_block_encrypt(block, key):

    if len(block) != 8:
        raise ValueError(f"DES requires 8-byte blocks")
    if len(key) != 8:
        raise ValueError(f"DES requires 8-byte key")
    
    cipher = CryptoDES.new(key, CryptoDES.MODE_ECB)
    return cipher.encrypt(block)


def des_block_decrypt(block, key):
    if len(block) != 8:
        raise ValueError(f"DES requires 8-byte blocks")
    if len(key) != 8:
        raise ValueError(f"DES requires 8-byte key")
    
    cipher = CryptoDES.new(key, CryptoDES.MODE_ECB)
    return cipher.decrypt(block)