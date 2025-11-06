from abc import ABC, abstractmethod


class PaddingMode:
    """Padding implementationss"""
    
    def zero_padding(data, block_size):
        """fill with 0x00 bytes"""
        padding_length = block_size - (len(data) % block_size)
        if padding_length == block_size:
            return data
        return data + b'\x00' * padding_length
    
    def des_padding(data, block_size):
        """fill with one 0x80 byte then 0x00 bytes"""
        padding_length = block_size - (len(data) % block_size)
        if padding_length == block_size:
            return data
        return data + b'\x80' + b'\x00' * (padding_length - 1)
    
    def schneier_ferguson_padding(data, block_size):
        """n bytes of value n"""
        padding_length = block_size - (len(data) % block_size)
        if padding_length == block_size:
            padding_length = block_size
        return data + bytes([padding_length] * padding_length)
    
    def remove_zero_padding(data):
        return data.rstrip(b'\x00')
    
    def remove_des_padding(data):
        for i in range(len(data) - 1, -1, -1):
            if data[i] == b'\x80':
                return data[:i]
            elif data[i] != b'\0x00':
                return data
        return data
    
    def remove_schneier_ferguson_padding(data):
        if not data:
            return data
        padding_length = data[-1]
        if padding_length > len(data):
            return data
        if all(b == padding_length for b in data[-padding_length:]):
            return data[:-padding_length]
        return data
        
    
class BlockCipherMode(ABC):
    
    def __init__(self, block_size_bits, encrypt_function, decrypt_function, key, iv):
        self.block_size = block_size_bits // 8
        self.encrypt_func = encrypt_function
        self.decrypt_func = decrypt_function
        self.key = key
        self.iv = iv
        
    @abstractmethod
    def encrypt(self, plaintext):
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext):
        pass
    
    def xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))
    

class ECBMode(BlockCipherMode):
    """Electronic Codebook Mode"""
    
    def encrypt(self, plaintext):
        result = b''
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]
            result += self.encrypt_func(block, self.key)
        return result
    
    def decrypt(self, ciphertext):
        result = b''
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            result += self.decrypt_func(block, self.key)
        return result

