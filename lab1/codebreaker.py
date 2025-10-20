
from crypto import decrypt_vigenere

def load(path='words_alpha.txt'):
    f = open(path, 'r')
    words = set(word.strip().upper() for word in f if word.strip())
    f.close()
    return words


def count_words(text, dictionary):
    if not dictionary:
        return 0
    
    words = []
    current_word = ""
    
    for char in text:
        if char.isalpha():
            current_word += char
        else:
            if current_word:
                words.append(current_word)
                current_word = ""
    
    if current_word:
        words.append(current_word)
    
    count = 0
    for word in words:
        if word in dictionary:
            count += 1
    
    return count
    

def breaker(ciphertext, possible_keys):
    dictionary = load()
    
    best_plaintext = ""
    best_count = 0
    best_key = ""
    
    for key in possible_keys:
        try:
            plaintext = decrypt_vigenere(ciphertext, key)
            
            word_count = count_words(plaintext, dictionary)
            
            if word_count > best_count:
                best_count = word_count
                best_plaintext = plaintext
                best_key = key
        except:
            continue
    
    print(f"key: {best_key}")
    
    return best_plaintext

ciphertext = "LXFOPV EF RNHR"
possible_keys = ["LEMON", "APPLE", "BANANA", "CHERRY"]

result = breaker(ciphertext, possible_keys)
print(f"text: {result}")
print()


f = open('words_alpha.txt', 'r')
possible_keys2 = [word.strip().upper() for word in f if word.strip()]

f = open('not_a_secret_message.txt', 'r')
secret_ciphertext = f.read().strip().upper()

result3 = breaker(secret_ciphertext, possible_keys2)
print(f"Secret message: {result3}")
