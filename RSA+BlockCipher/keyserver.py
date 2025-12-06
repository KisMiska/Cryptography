"""
Listens on port 8000 and responds to:
1. REGISTER <client_id> <public_key> - Store/update public key
2. GETKEY <client_id> - Retunr public key
"""

import socket
import threading

class KeyServer:
    
    def __init__(self, host='localhost', port=8000):
        self.host = host
        self.port = port
        self.keys = {}                  # client_id -> public_key
        self.lock = threading.Lock()
        
    def start(self):
        """Start the server and listen for connections"""
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(10)
        
        print(f"[KeyServer] Started on {self.host}:{self.port}")
        print(f"[KeyServer] Waiting for client requests...")
        
        
        try:
            while True:
                client_sock, addr = server_socket.accept()
                thread = threading.Thread(target=self.handle_client, args=(client_sock, addr))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("\n[KeyServer] Shutting down...")
            server_socket.close()
            
        
    def handle_client(self, client_sock, addr):
        """Handle a single client request"""
        
        try:
            
            data = client_sock.recv(10240).decode('utf-8')
            
            if not data:
                return
            
            parts = data.split(" ", 2)
            command = parts[0]
            
            if command == 'REGISTER':
                # REGISTER <client_id> <public_key>
                
                client_id = parts[1]
                public_key = parts[2]
                
                with self.lock:
                    self.keys[client_id] = public_key
                
                print(f"[KeyServer] Registered client {client_id} from {addr}")
                client_sock.sendall(b"OK")
                
            elif command == "GETKEY":
                # GETKEY <client_id>
                
                client_id = parts[1]
                
                with self.lock:
                    public_key = self.keys.get(client_id)
                
                if public_key:
                    print(f"[KeyServer] Sent public key to client {client_id} to {addr}")
                    client_sock.sendall(public_key.encode('utf-8'))
                else:
                    print(f"[KeyServer] Client {client_id} not found (requested by {addr})")
                    client_sock.sendall(b"ERROR: Client not found")
                    
            else:
                print(f"[KeyServer] Unknown command: {command}")
                client_sock.sendall(b"ERROR: Unknown command")
                    
        except Exception as e:
            print(f"[KeyServer] Error handling client {addr}: {e}")
        finally:
            client_sock.close()
        
if __name__ == '__main__':
    server = KeyServer()
    server.start()