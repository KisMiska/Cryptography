import socket
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class TestKeyServer:
    def __init__(self):
        self.keyserver_host = 'localhost'
        self.keyserver_port = 8000
        
    def test_register_client(self):
        """Test client registration"""
        print("\n=== Test 1: Register Client ===")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Connect to KeyServer
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.keyserver_host, self.keyserver_port))
            
            # Send registration
            request = f"REGISTER TEST_CLIENT_001 {public_pem}"
            sock.sendall(request.encode('utf-8'))
            
            # Get response
            response = sock.recv(1024).decode('utf-8')
            
            if response == "OK":
                print("Registration successful")
                return True
            else:
                print(f"Registration failed: {response}")
                return False
        except Exception as e:
            print(f"est failed: {e}")
            return False
        finally:
            sock.close()
    
    def test_get_key(self):
        """Test key retrieval"""
        print("\n=== Test 2: Retrieve Public Key ===")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.keyserver_host, self.keyserver_port))
            
            # Request key
            request = "GETKEY TEST_CLIENT_001"
            sock.sendall(request.encode('utf-8'))
            
            # Get response
            response = sock.recv(10240).decode('utf-8')
            
            if response.startswith("-----BEGIN PUBLIC KEY-----"):
                print("Key retrieval successful")
                print(f"  Retrieved {len(response)} byte PEM")
                
                # Try to parse it
                public_key = serialization.load_pem_public_key(
                    response.encode('utf-8'),
                    backend=default_backend()
                )
                print("Key is valid RSA public key")
                return True
            else:
                print(f"Key retrieval failed: {response}")
                return False
        except Exception as e:
            print(f"Test failed: {e}")
            return False
        finally:
            sock.close()
    
    def test_get_nonexistent_key(self):
        """Test retrieving non-existent client"""
        print("\n=== Test 3: Retrieve Non-existent Key ===")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.keyserver_host, self.keyserver_port))
            
            request = "GETKEY NONEXISTENT_CLIENT"
            sock.sendall(request.encode('utf-8'))
            
            response = sock.recv(1024).decode('utf-8')
            
            if response.startswith("ERROR"):
                print("Correctly returned error for non-existent client")
                return True
            else:
                print(f"Should have returned error: {response}")
                return False
        except Exception as e:
            print(f"Test failed: {e}")
            return False
        finally:
            sock.close()
    
    def test_update_key(self):
        """Test updating existing key"""
        print("\n=== Test 4: Update Existing Key ===")
        
        # Generate new key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.keyserver_host, self.keyserver_port))
            
            # Re-register same client with new key
            request = f"REGISTER TEST_CLIENT_001 {public_pem}"
            sock.sendall(request.encode('utf-8'))
            
            response = sock.recv(1024).decode('utf-8')
            
            if response == "OK":
                print("Key update successful")
                
                # Verify new key is stored
                sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.keyserver_host, self.keyserver_port))
                
                sock.sendall(b"GETKEY TEST_CLIENT_001")
                retrieved = sock.recv(10240).decode('utf-8')
                
                if retrieved == public_pem:
                    print("Updated key verified")
                    return True
                else:
                    print("Retrieved key doesn't match updated key")
                    return False
            else:
                print(f"Update failed: {response}")
                return False
        except Exception as e:
            print(f"Test failed: {e}")
            return False
        finally:
            sock.close()
    
    def test_concurrent_requests(self):
        """Test handling multiple concurrent requests"""
        print("\n=== Test 5: Concurrent Requests ===")
        
        results = []
        
        def make_request(client_id):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.keyserver_host, self.keyserver_port))
                sock.sendall(f"GETKEY {client_id}".encode('utf-8'))
                response = sock.recv(1024)
                sock.close()
                results.append(True)
            except Exception as e:
                print(f"  Request failed: {e}")
                results.append(False)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=make_request, args=("TEST_CLIENT_001",))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        if len(results) == 5 and all(results):
            print(f"All {len(results)} concurrent requests succeeded")
            return True
        else:
            print(f"Only {sum(results)}/{len(results)} requests succeeded")
            return False
    
    def run_all_tests(self):
        """Run all tests"""
        print("=" * 50)
        print("KeyServer Unit Tests")
        print("=" * 50)
        print("Make sure KeyServer is running on localhost:8000")
        input("Press Enter to start tests...")
        
        tests = [
            self.test_register_client,
            self.test_get_key,
            self.test_get_nonexistent_key,
            self.test_update_key,
            self.test_concurrent_requests
        ]
        
        results = []
        for test in tests:
            results.append(test())
            time.sleep(0.5)
        
        print("\n" + "=" * 50)
        print(f"Results: {sum(results)}/{len(results)} tests passed")
        print("=" * 50)
        
        if all(results):
            print("All tests passed!")
        else:
            print("Some tests failed")


if __name__ == '__main__':
    tester = TestKeyServer()
    tester.run_all_tests()