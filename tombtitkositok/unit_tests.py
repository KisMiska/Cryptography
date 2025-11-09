
import pytest
import os
import tempfile
from block_cipher import (Framework, PaddingMode,ECBMode, CBCMode, CFBMode, OFBMode, CTRMode)
from my_custom_cipher import ervin_block_encrypt, ervin_block_decrypt
from des_cipher import des_block_encrypt, des_block_decrypt
from utils.config_manager import ConfigManager


class TestPaddingModes:

    def test_zero_padding(self):
        data = b"Hello"
        padded = PaddingMode.zero_padding(data, 8)
        assert len(padded) == 8
        assert padded == b"Hello\x00\x00\x00"
        unpadded = PaddingMode.remove_zero_padding(padded)
        assert unpadded == data
    
    def test_des_padding(self):
        data = b"Hello"
        padded = PaddingMode.des_padding(data, 8)
        assert len(padded) == 8
        assert padded == b"Hello\x80\x00\x00"
        unpadded = PaddingMode.remove_des_padding(padded)
        assert unpadded == data
    
    def test_schneier_ferguson_padding(self):
        data = b"Hello"
        padded = PaddingMode.schneier_ferguson_padding(data, 8)
        assert len(padded) == 8
        assert padded == b"Hello\x03\x03\x03"
        unpadded = PaddingMode.remove_schneier_ferguson_padding(padded)
        assert unpadded == data



class TestCustomCipher:
    def test_encryption_decryption(self):
        key = b"secretkey"
        plaintext = b"Hello ERVIN!!!!!"
        
        ciphertext = ervin_block_encrypt(plaintext, key)
        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)
        
        decrypted = ervin_block_decrypt(ciphertext, key)
        assert decrypted == plaintext
    
    def test_different_keys_produce_different_ciphertext(self):
        plaintext = b"ABC abc A!B!"
        key1 = b"key1"
        key2 = b"key2"
        
        cipher1 = ervin_block_encrypt(plaintext, key1)
        cipher2 = ervin_block_encrypt(plaintext, key2)
        assert cipher1 != cipher2
    
    def test_empty_key_raises_error(self):
        with pytest.raises(ValueError):
            ervin_block_encrypt(b"data", b"")


class TestBlockCipherModes:

    @pytest.fixture
    def test_data(self):
        return b"This is test data for encryption!!"  # 34 bytes
    
    @pytest.fixture
    def key(self):
        return b"testkeyy"
    
    @pytest.fixture
    def iv(self):
        return b"initvect"
    
    def test_ecb_mode(self, test_data, key, iv):
        config = {
            'block_size_bits': 64,
            'mode': 'ECB',
            'padding': 'schneier_ferguson',
        }
        
        framework = Framework(config)
        
        ciphertext = framework.encrypt(test_data, ervin_block_encrypt, key)
        plaintext = framework.decrypt(
            ciphertext, ervin_block_decrypt, ervin_block_encrypt, key
        )
        
        assert plaintext == test_data
    
    def test_cbc_mode(self, test_data, key, iv):
        config = {
            'block_size_bits': 64,
            'mode': 'CBC',
            'padding': 'schneier_ferguson',
            'iv': iv
        }
        
        framework = Framework(config)
        
        ciphertext = framework.encrypt(test_data, ervin_block_encrypt, key)
        plaintext = framework.decrypt(
            ciphertext, ervin_block_decrypt, ervin_block_encrypt, key
        )
        
        assert plaintext == test_data
    
    def test_cfb_mode(self, test_data, key, iv):
        config = {
            'block_size_bits': 64,
            'mode': 'CFB',
            'padding': 'schneier_ferguson',
            'iv': iv
        }
        
        framework = Framework(config)
        
        ciphertext = framework.encrypt(test_data, ervin_block_encrypt, key)
        plaintext = framework.decrypt(
            ciphertext, ervin_block_decrypt, ervin_block_encrypt, key
        )
        
        assert plaintext == test_data
    
    def test_ofb_mode(self, test_data, key, iv):
        config = {
            'block_size_bits': 64,
            'mode': 'OFB',
            'padding': 'schneier_ferguson',
            'iv': iv
        }
        
        framework = Framework(config)
        
        ciphertext = framework.encrypt(test_data, ervin_block_encrypt, key)
        plaintext = framework.decrypt(
            ciphertext, ervin_block_decrypt, ervin_block_encrypt, key
        )
        
        assert plaintext == test_data
    
    def test_ctr_mode(self, test_data, key, iv):
        config = {
            'block_size_bits': 64,
            'mode': 'CTR',
            'padding': 'schneier_ferguson',
            'iv': iv
        }
        
        framework = Framework(config)
        
        ciphertext = framework.encrypt(test_data, ervin_block_encrypt, key)
        plaintext = framework.decrypt(
            ciphertext, ervin_block_decrypt, ervin_block_encrypt, key
        )
        
        assert plaintext == test_data


class TestConfigManager:
    
    def test_load_valid_config(self):
        config_data = {
            "algorithm": "ervin",
            "block_size_bits": 64,
            "mode": "CBC",
            "padding": "schneier_ferguson",
            "key": "0123456789ABCDEF",
            "iv": "FEDCBA9876543210"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', 
                                         delete=False) as f:
            import json
            json.dump(config_data, f)
            config_path = f.name
        
        try:
            config = ConfigManager.load_config(config_path)
            assert config['algorithm'] == 'ervin'
            assert config['block_size_bits'] == 64
            assert isinstance(config['key'], bytes)
            assert isinstance(config['iv'], bytes)
        finally:
            os.unlink(config_path)
    
    def test_missing_required_field(self):
        config_data = {
            "algorithm": "ervin",
            "block_size_bits": 64,
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            import json
            json.dump(config_data, f)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Missing required fields"):
                ConfigManager.load_config(config_path)
        finally:
            os.unlink(config_path)
    
    def test_invalid_algorithm(self):
        config_data = {
            "algorithm": "invalid",
            "block_size_bits": 64,
            "mode": "ECB",
            "padding": "zero",
            "key": "0123456789ABCDEF"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', 
                                         delete=False) as f:
            import json
            json.dump(config_data, f)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Invalid algorithm"):
                ConfigManager.load_config(config_path)
        finally:
            os.unlink(config_path)
    
    def test_missing_iv_for_cbc(self):
        config_data = {
            "algorithm": "ervin",
            "block_size_bits": 64,
            "mode": "CBC",
            "padding": "zero",
            "key": "0123456789ABCDEF"
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            import json
            json.dump(config_data, f)
            config_path = f.name
        
        try:
            with pytest.raises(ValueError, match="IV is required"):
                ConfigManager.load_config(config_path)
        finally:
            os.unlink(config_path)


class TestIntegration:
    
    def test_encrypt_decrypt_large_data(self):
        test_data = b"A" * 2000
        
        config = {
            'block_size_bits': 128,
            'mode': 'CBC',
            'padding': 'schneier_ferguson',
            'iv': b'\x00' * 16
        }
        
        key = b"mysecretkey12345"
        
        framework = Framework(config)
        ciphertext = framework.encrypt(test_data, ervin_block_encrypt, key)
        plaintext = framework.decrypt(
            ciphertext, ervin_block_decrypt, ervin_block_encrypt, key
        )
        
        assert plaintext == test_data
        assert len(ciphertext) >= len(test_data)
    
    def test_des_full_workflow(self):
        test_data = b"Test data for DES encryption and decryption!"
        
        config = {
            'block_size_bits': 64,
            'mode': 'CBC',
            'padding': 'schneier_ferguson',
            'iv': b'\x00' * 8
        }
        
        key = b"deskey!!"
        
        framework = Framework(config)
        ciphertext = framework.encrypt(test_data, des_block_encrypt, key)
        plaintext = framework.decrypt(
            ciphertext, des_block_decrypt, des_block_encrypt, key
        )
        
        assert plaintext == test_data