"""
Secure Client
1. RSA-2048 for key exchange
2. Block cipher (ERVIN or DES) for encrypted messages
"""

import socket
import threading
import json
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

import sys
sys.path.append('.')
from block_cipher import Framework
from my_custom_cipher import ervin_block_encrypt, ervin_block_decrypt
from des_cipher import des_block_encrypt, des_block_decrypt


class Client:
    def __init__(self, client_id, keyserver_host='localhost', keyserver_port=8000):
        self.client_id = client_id
        self.port = int(client_id)  # Using client_id as port
        self.host = 'localhost'
        self.keyserver_host = keyserver_host
        self.keyserver_port = keyserver_port
        
        # RSA key pair
        print(f"[Client {self.client_id}] Generating RSA-2048 key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print(f"[Client {self.client_id}] RSA key pair generated")
        
        # Supported algorithms
        self.supported_algorithms = {
            'ERVIN-128-CBC': (ervin_block_encrypt, ervin_block_decrypt, 128),
            'ERVIN-128-CFB': (ervin_block_encrypt, ervin_block_decrypt, 128),
            'DES-64-CBC': (des_block_encrypt, des_block_decrypt, 64),
        }
        
        self.peer_public_key = None
        self.session_key = None
        self.agreed_algorithm = None
        self.server_socket = None
        
    def register_with_keyserver(self):
        """Register this clients public key with KeyServer"""
        print(f"[Client {self.client_id}] Registering with KeyServer...")
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.keyserver_host, self.keyserver_port))
        
        request = f"REGISTER {self.client_id} {public_pem}"
        sock.sendall(request.encode('utf-8'))
        
        response = sock.recv(1024).decode('utf-8')
        sock.close()
        
        print(f"[Client {self.client_id}] Registration response: {response}")
        
    def get_peer_public_key(self, peer_id):
        """Retrieve peers public key from KeyServer"""
        print(f"[Client {self.client_id}] Requesting public key for client {peer_id}...")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.keyserver_host, self.keyserver_port))
        
        request = f"GETKEY {peer_id}"
        sock.sendall(request.encode('utf-8'))
        
        response = sock.recv(10240).decode('utf-8')
        sock.close()
        
        if response.startswith("ERROR"):
            print(f"[Client {self.client_id}] {response}")
            return None
        
        # Parse PEM
        public_key = serialization.load_pem_public_key(
            response.encode('utf-8'),
            backend=default_backend()
        )
        
        print(f"[Client {self.client_id}] Received public key for client {peer_id}")
        return public_key
    
    def start_listening(self):
        """Start listening connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)
        
        print(f"[Client {self.client_id}] Listening on {self.host}:{self.port}")
        
        thread = threading.Thread(target=self.accept_connections)
        thread.daemon = True
        thread.start()
    
    def accept_connections(self):
        """Accept incoming connections"""
        while True:
            try:
                conn, addr = self.server_socket.accept()
                print(f"[Client {self.client_id}] Accepted connection from {addr}")
                thread = threading.Thread(target=self.handle_peer, args=(conn,))
                thread.daemon = True
                thread.start()
            except:
                break
    
    def handle_peer(self, conn):
        """Handle incoming messages"""
        try:
            while True:
                # Receive message length first (4 bytes)
                len_bytes = conn.recv(4)
                if not len_bytes:
                    break
                
                msg_len = int.from_bytes(len_bytes, 'big')
                
                # Receive full message
                data = b''
                while len(data) < msg_len:
                    chunk = conn.recv(min(msg_len - len(data), 4096))
                    if not chunk:
                        break
                    data += chunk
                
                msg = json.loads(data.decode('utf-8'))
                
                if msg['type'] == 'KEY_EXCHANGE':
                    self.handle_key_exchange(conn, msg)
                elif msg['type'] == 'ENCRYPTED_MSG':
                    self.handle_encrypted_message(msg)
                    
        except Exception as e:
            print(f"[Client {self.client_id}] Error handling peer: {e}")
        finally:
            conn.close()
    
    def handle_key_exchange(self, conn, msg):
        """Handle key exchange"""
        print(f"[Client {self.client_id}] Received key exchange proposal")
        print(f"[Client {self.client_id}] Peer algorithms: {msg['algorithms']}")
        
        # Find common algorithm
        common = [alg for alg in msg['algorithms'] if alg in self.supported_algorithms]
        
        if not common:
            print(f"[Client {self.client_id}] ERROR: No common algorithms!")
            response = {'type': 'KEY_EXCHANGE_RESPONSE', 'status': 'ERROR', 'reason': 'No common algorithm'}
        else:
            self.agreed_algorithm = common[0]
            print(f"[Client {self.client_id}] Agreed on algorithm: {self.agreed_algorithm}")
            
            # Decrypt the session key
            encrypted_key = bytes.fromhex(msg['encrypted_key'])
            self.session_key = self.private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            print(f"[Client {self.client_id}] Decrypted session key: {self.session_key.hex()}")
            
            response = {
                'type': 'KEY_EXCHANGE_RESPONSE',
                'status': 'OK',
                'algorithm': self.agreed_algorithm
            }
        
        # Send response
        response_bytes = json.dumps(response).encode('utf-8')
        conn.sendall(len(response_bytes).to_bytes(4, 'big') + response_bytes)
    
    def handle_encrypted_message(self, msg):
        """Decrypt and display received message"""
        print(f"[Client {self.client_id}] Received encrypted message")
        
        ciphertext = bytes.fromhex(msg['ciphertext'])
        
        # Decrypt using agreed algorithm
        encrypt_func, decrypt_func, block_size = self.supported_algorithms[self.agreed_algorithm]
        mode = self.agreed_algorithm.split('-')[2]  # CBC, CFB, etc.
        
        config = {
            'block_size_bits': block_size,
            'mode': mode,
            'padding': 'schneier_ferguson',
            'iv': bytes.fromhex(msg['iv'])
        }
        
        framework = Framework(config)
        plaintext = framework.decrypt(ciphertext, decrypt_func, encrypt_func, self.session_key)
        
        print(f"[Client {self.client_id}] Decrypted message: {plaintext.decode('utf-8')}")
    
    def initiate_key_exchange(self, peer_id):
        """Initiate key exchange with peer"""
        print(f"\n[Client {self.client_id}] === Starting Key Exchange with Client {peer_id} ===")
        
        # Get peers public key
        self.peer_public_key = self.get_peer_public_key(peer_id)
        if not self.peer_public_key:
            return False
        
        # Generate random session key (16 bytes for 128-bit)
        self.session_key = os.urandom(16)
        print(f"[Client {self.client_id}] Generated session key: {self.session_key.hex()}")
        
        # Encrypt session key with peers public key
        encrypted_key = self.peer_public_key.encrypt(
            self.session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        print(f"[Client {self.client_id}] Encrypted session key with peer's RSA public key")
        
        # Connect to peer
        peer_port = int(peer_id)
        peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer_sock.connect(('localhost', peer_port))
        
        # Send key exchange proposal
        msg = {
            'type': 'KEY_EXCHANGE',
            'algorithms': list(self.supported_algorithms.keys()),
            'encrypted_key': encrypted_key.hex()
        }
        
        msg_bytes = json.dumps(msg).encode('utf-8')
        peer_sock.sendall(len(msg_bytes).to_bytes(4, 'big') + msg_bytes)
        
        print(f"[Client {self.client_id}] Sent key exchange proposal")
        
        # Wait for response
        len_bytes = peer_sock.recv(4)
        msg_len = int.from_bytes(len_bytes, 'big')
        response = json.loads(peer_sock.recv(msg_len).decode('utf-8'))
        
        if response['status'] == 'OK':
            self.agreed_algorithm = response['algorithm']
            print(f"[Client {self.client_id}] Key exchange successful!")
            print(f"[Client {self.client_id}] Algorithm: {self.agreed_algorithm}")
            print(f"[Client {self.client_id}] === Key Exchange Complete ===\n")
            return peer_sock
        else:
            print(f"[Client {self.client_id}] Key exchange failed: {response.get('reason')}")
            peer_sock.close()
            return None
    
    def send_encrypted_message(self, peer_sock, message):
        """Send encrypted message to peer"""
        print(f"[Client {self.client_id}] Encrypting message: '{message}'")
        
        plaintext = message.encode('utf-8')
        
        # Encrypt using agreed algorithm
        encrypt_func, decrypt_func, block_size = self.supported_algorithms[self.agreed_algorithm]
        mode = self.agreed_algorithm.split('-')[2]
        
        # Generate random IV
        iv = os.urandom(block_size // 8)
        
        config = {
            'block_size_bits': block_size,
            'mode': mode,
            'padding': 'schneier_ferguson',
            'iv': iv
        }
        
        framework = Framework(config)
        ciphertext = framework.encrypt(plaintext, encrypt_func, self.session_key)
        
        print(f"[Client {self.client_id}] Ciphertext length: {len(ciphertext)} bytes")
        
        # Send encrypted message
        msg = {
            'type': 'ENCRYPTED_MSG',
            'ciphertext': ciphertext.hex(),
            'iv': iv.hex()
        }
        
        msg_bytes = json.dumps(msg).encode('utf-8')
        peer_sock.sendall(len(msg_bytes).to_bytes(4, 'big') + msg_bytes)
        
        print(f"[Client {self.client_id}] Message sent")


def demo_client_1():
    """Client 8001"""
    client = Client('8001')
    client.register_with_keyserver()
    client.start_listening()
    
    input("[Client 8001] Press Enter when Client 8002 is ready...")
    
    # Initiate key exchange
    peer_sock = client.initiate_key_exchange('8002')
    
    if peer_sock:
        # Send 2 messages > 256 chars each
        msg1 = "A" * 300  # 300 characters
        msg2 = "Hello from Client 8001! " * 20  # ~480 characters
        
        print(f"\n[Client 8001] === Sending Message 1 ({len(msg1)} chars) ===")
        client.send_encrypted_message(peer_sock, msg1)
        
        import time
        time.sleep(2)
        
        print(f"\n[Client 8001] === Sending Message 2 ({len(msg2)} chars) ===")
        client.send_encrypted_message(peer_sock, msg2)
        
        # Keep listening
        input("\n[Client 8001] Press Enter to exit...")
        peer_sock.close()


def demo_client_2():
    """Client 8002 - Responds to Client 8001"""
    client = Client('8002')
    client.register_with_keyserver()
    client.start_listening()
    
    print("[Client 8002] Ready and listening...")
    
    # Wait for key exchange from Client 8001
    input("\n[Client 8002] Press Enter when ready to send messages to 8001...")
    
    # Now initiate connection back to 8001
    peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_sock.connect(('localhost', 8001))
    
    # Send 2 messages > 256 chars each
    msg1 = "B" * 350  # 350 characters
    msg2 = "Response from Client 8002! " * 25  # ~675 characters
    
    print(f"\n[Client 8002] === Sending Message 1 ({len(msg1)} chars) ===")
    client.send_encrypted_message(peer_sock, msg1)
    
    import time
    time.sleep(2)
    
    print(f"\n[Client 8002] === Sending Message 2 ({len(msg2)} chars) ===")
    client.send_encrypted_message(peer_sock, msg2)
    
    input("\n[Client 8002] Press Enter to exit...")
    peer_sock.close()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python secure_client.py <1|2>")
        print("  1 - Run as Client 8001")
        print("  2 - Run as Client 8002")
        sys.exit(1)
    
    if sys.argv[1] == '1':
        demo_client_1()
    else:
        demo_client_2()