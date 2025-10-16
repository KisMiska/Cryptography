#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <YOUR NAME>
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    """Encrypt plaintext using a Caesar cipher.

    Add more implementation details here.
    """
    ciphertext = []
    for char in plaintext:
        if char.isalpha():
            new = ord(char) - ord('A')
            new = (new + 3) % 26
            ciphertext.append(chr(new + ord('A')))
        else:
            ciphertext.append(char)
        
    return ''.join(ciphertext)


def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher.

    Add more implementation details here.
    """
    plaintext = []
    for char in ciphertext:
        if char.isalpha():
            new = ord(char) - ord('A')
            new = (new - 3) % 26
            plaintext.append(chr(new + ord('A')))
        else:
            plaintext.append(char)
            
    return ''.join(plaintext)
    

# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    ciphertext = []
    len_keyw = len(keyword)
    
    for i, char in enumerate(plaintext):
        shift = ord(keyword[i % len_keyw]) - ord('A')
        new = (ord(char) - ord('A') + shift) % 26
        ciphertext.append(chr(new + ord('A')))
    
    return ''.join(ciphertext)


def decrypt_vigenere(ciphertext, keyword):
    """Decrypt ciphertext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    plaintext = []
    len_keyw = len(keyword)
    
    for i, char in enumerate(ciphertext):
        shift = ord(keyword[i % len_keyw]) - ord('A')
        new = (ord(char) - ord('A') - shift) % 26
        plaintext.append(chr(new + ord('A')))
    
    return ''.join(plaintext)
    

# Scytale Cipher

def encrypt_scytale(plaintext, circumference):
    """Encrypt plaintext using a Scytale cipher"""
    
    if circumference <= 0:
        raise ValueError("Circumference must be positive")
    
    length = len(plaintext)
    num_cols = (length + circumference - 1) // circumference
    padded_length = num_cols * circumference
    plaintext = plaintext + ' ' * (padded_length - length)
    
    ciphertext = []
    for row in range(circumference):
        for col in range(num_cols):
            index = col * circumference + row
            if index < len(plaintext):
                ciphertext.append(plaintext[index])
    
    return ''.join(ciphertext)


def decrypt_scytale(ciphertext, circumference):
    """Decrypt ciphertext using a Scytale cipher"""
    
    if circumference <= 0:
        raise ValueError("Circumference must be positive")
    
    length = len(ciphertext)
    num_cols = (length + circumference - 1) // circumference
    
    result = []
    for col in range(num_cols):
        for row in range(circumference):
            index = row * num_cols + col
            if index < length:
                result.append(ciphertext[index])
    
    return ''.join(result).rstrip()

# Railfence cipher

def encrypt_railfence(plaintext, num_rails):
    """Encrypt plaintext using a Railfence cipher"""
    
    if num_rails <= 1:
        return plaintext
    
    rails = [[] for _ in range(num_rails)]
    rail = 0
    direction = 1
    
    for char in plaintext:
        rails[rail].append(char)
        rail += direction
        
        if rail == 0 or rail == num_rails - 1:
            direction *= -1
    
    return ''.join(''.join(rail) for rail in rails)

def decrypt_railfence(ciphertext, num_rails):
    """Decrypt ciphertext using a Railfence cipher"""
    
    if num_rails <= 1:
        return ciphertext

    rail_lengths = [0] * num_rails
    rail = 0
    direction = 1
    
    for _ in ciphertext:
        rail_lengths[rail] += 1
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1
    
    rails = []
    index = 0
    for length in rail_lengths:
        rails.append(list(ciphertext[index:index + length]))
        index += length
    
    result = []
    rail = 0
    direction = 1
    rail_indices = [0] * num_rails
    
    for _ in ciphertext:
        result.append(rails[rail][rail_indices[rail]])
        rail_indices[rail] += 1
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1
    
    return ''.join(result)


# Merkle-Hellman Knapsack Cryptosystem

def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    raise NotImplementedError  # Your implementation here

def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    raise NotImplementedError  # Your implementation here


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """
    raise NotImplementedError  # Your implementation here

def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    raise NotImplementedError  # Your implementation here

