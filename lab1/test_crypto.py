import pytest

from crypto import (encrypt_caesar, decrypt_caesar,
                    encrypt_vigenere, decrypt_vigenere,
                    encrypt_scytale, decrypt_scytale,
                    encrypt_railfence, decrypt_railfence)

class TestCaesarCipher:
    
    def test1(self):
        assert encrypt_caesar("PYTHON") == b"S\\WKRQ"
    
    def test2(self):
        assert decrypt_caesar("SBWKRQ") == b"P?THON"
    
    def test3(self):
        assert encrypt_caesar("HELLO!") == b"KHOOR$"
    
    def test4(self):
        original = "ABHVJFUFJJHJH"
        encrypted = encrypt_caesar(original)
        decrypted = decrypt_caesar(encrypted).decode('utf-8')
        assert decrypted == original
    
    def test5(self):
        assert encrypt_caesar("A") == b"D"
    
    def test6(self):
        assert decrypt_caesar(b"D") == b"A"
        
    
class TestVigenereCipher:
    
    def test1(self):
        assert encrypt_vigenere("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    
    def test2(self):
        assert decrypt_vigenere("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"
    
    def test3(self):
        plaintext = "HELLO"
        ciphertext = encrypt_vigenere(plaintext, "A")
        assert ciphertext == plaintext
    
    def test4(self):
        assert encrypt_vigenere("HI", "LEMON") == "SM"
    
    def test5(self):
        assert decrypt_vigenere("TS", "LEMON") == "IO"
    
    def test6(self):
        plaintext = "SECRETMESSAGE"
        key = "PASSWORD"
        encrypted = encrypt_vigenere(plaintext, key)
        decrypted = decrypt_vigenere(encrypted, key)
        assert decrypted == plaintext
    
    def test7(self):
        assert encrypt_vigenere("A", "B") == "B"
    
    def test8(self):
        assert encrypt_vigenere("Z", "Z") == "Y" 
        

class TestScytaleCipher:
    
    def test1(self):
        result = encrypt_scytale("IAMHURTVERYBADLYHELP", 5)
        assert result == "IRYYATBHMVAEHEDLURLP"
    
    def test2(self):
        result = decrypt_scytale("IRYYATBHMVAEHEDLURLP", 5)
        assert result == "IAMHURTVERYBADLYHELP"
    
    def test3(self):
        original = "NKBJHKGLGJHBILHBK"
        circumference = 4
        encrypted = encrypt_scytale(original, circumference)
        decrypted = decrypt_scytale(encrypted, circumference)
        assert decrypted == original
    
    def test4(self):
        plaintext = "HELLO"
        assert encrypt_scytale(plaintext, 1) == plaintext
    
    def test5(self):
        plaintext = "HELLO"
        encrypted = encrypt_scytale(plaintext, 5)
        decrypted = decrypt_scytale(encrypted, 5)
        assert decrypted == plaintext
    
    def test6(self):
        with pytest.raises(ValueError):
            encrypt_scytale("HELLO", 0)
        with pytest.raises(ValueError):
            encrypt_scytale("HELLO", -1)
    
    def test7(self):
        plaintext = "HELLO"
        circumference = 2
        encrypted = encrypt_scytale(plaintext, circumference)
        decrypted = decrypt_scytale(encrypted, circumference)
        assert decrypted == plaintext
        

class TestRailfenceCipher:
    
    def test1(self):
        result = encrypt_railfence("WEAREDISCOVEREDFLEEATONCE", 3)
        assert result == "WECRLTEERDSOEEFEAOCAIVDEN"
    
    def test2(self):
        result = decrypt_railfence("WECRLTEERDSOEEFEAOCAIVDEN", 3)
        assert result == "WEAREDISCOVEREDFLEEATONCE"
    
    def test3(self):
        original = "JHKGOIUYONJ"
        num_rails = 4
        encrypted = encrypt_railfence(original, num_rails)
        decrypted = decrypt_railfence(encrypted, num_rails)
        assert decrypted == original
    
    def test4(self):
        plaintext = "HELLO"
        assert encrypt_railfence(plaintext, 1) == plaintext
        assert decrypt_railfence(plaintext, 1) == plaintext
    
    def test5(self):
        plaintext = "HELLO"
        encrypted = encrypt_railfence(plaintext, 2)
        decrypted = decrypt_railfence(encrypted, 2)
        assert decrypted == plaintext
    
    def test6(self):
        plaintext = "HELLO"
        encrypted = encrypt_railfence(plaintext, 5)
        decrypted = decrypt_railfence(encrypted, 5)
        assert decrypted == plaintext
    
    def test7(self):
        plaintext = "ANJKLHILUTGUY"
        encrypted = encrypt_railfence(plaintext, 10)
        decrypted = decrypt_railfence(encrypted, 10)
        assert decrypted == plaintext
    
    def test8(self):
        plaintext = "A"
        encrypted = encrypt_railfence(plaintext, 3)
        decrypted = decrypt_railfence(encrypted, 3)
        assert decrypted == plaintext