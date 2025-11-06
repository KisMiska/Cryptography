

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
        
    

    