import os
import hashlib
import base64
import secrets
import string
import numpy as np
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

class CryptographyTool:
    def __init__(self):
        self.rsa_key_pair = None
        
    def clear_screen(self):
        """Membersihkan layar terminal"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_menu(self):
        """Menampilkan menu utama"""
        print("=" * 58)
        print("SISTEM KRIPTOGRAFI KOMPREHENSIF || BY RAKKA EVANDRA RAZAAN")
        print("=" * 58)
        print("\nPILIH JENIS ALGORITMA:")
        print("1.  Symmetric Key Cryptography")
        print("2.  Asymmetric Key Cryptography")
        print("3.  Hash Functions")
        print("4.  Classical Ciphers")
        print("5.  Keluar")
        print("-" * 60)
        
    def symmetric_menu(self):
        """Menu untuk symmetric key cryptography"""
        print("\nSYMMETRIC KEY CRYPTOGRAPHY")
        print("1.  AES-128")
        print("2.  AES-192")
        print("3.  AES-256")
        print("4.  Kembali ke Menu Utama")
        
        choice = input("\nPilih algoritma (1-4): ")
        return choice
    
    def asymmetric_menu(self):
        """Menu untuk asymmetric key cryptography"""
        print("\nASYMMETRIC KEY CRYPTOGRAPHY")
        print("1.  RSA (Encryption/Decryption)")
        print("2.  RSA (Digital Signature)")
        print("3.  Diffie-Hellman Key Exchange (Simulasi)")
        print("4.  DSA (Digital Signature Algorithm)")
        print("5.  Kembali ke Menu Utama")
        
        choice = input("\nPilih algoritma (1-5): ")
        return choice
    
    def hash_menu(self):
        """Menu untuk hash functions"""
        print("\nHASH FUNCTIONS")
        print("1.  SHA-256")
        print("2.  SHA-512")
        print("3.  Kembali ke Menu Utama")
        
        choice = input("\nPilih algoritma (1-3): ")
        return choice
    
    def classical_menu(self):
        """Menu untuk classical ciphers"""
        print("\nCLASSICAL CIPHERS")
        print("1.  Shift Cipher (Caesar Cipher)")
        print("2.  Substitution Cipher")
        print("3.  Vigenere Cipher")
        print("4.  Affine Cipher")
        print("5.  Hill Cipher")
        print("6.  Transportation Cipher (Transposition)")
        print("7.  Kembali ke Menu Utama")
        
        choice = input("\nPilih cipher (1-7): ")
        return choice
    
    # =============== SYMMETRIC KEY METHODS ===============
    
    def generate_aes_key(self, key_size):
        """Generate key untuk AES"""
        if key_size == 128:
            key = secrets.token_bytes(16)  # 16 bytes = 128 bits
        elif key_size == 192:
            key = secrets.token_bytes(24)  # 24 bytes = 192 bits
        elif key_size == 256:
            key = secrets.token_bytes(32)  # 32 bytes = 256 bits
        else:
            raise ValueError("Ukuran key tidak valid")
        
        # Generate IV (Initialization Vector)
        iv = secrets.token_bytes(16)
        return key, iv
    
    def aes_encrypt(self, plaintext, key_size):
        """Enkripsi dengan AES"""
        try:
            key, iv = self.generate_aes_key(key_size)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Padding plaintext agar sesuai dengan block size
            padded_plaintext = pad(plaintext.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
            
            # Gabungkan IV dan ciphertext untuk dikembalikan
            encrypted_data = iv + ciphertext
            
            return {
                'ciphertext': base64.b64encode(encrypted_data).decode(),
                'key': base64.b64encode(key).decode(),
                'iv': base64.b64encode(iv).decode()
            }
        except Exception as e:
            return f"Error: {str(e)}"
    
    def aes_decrypt(self, encrypted_data, key, iv=None):
        """Dekripsi dengan AES"""
        try:
            # Decode dari base64
            encrypted_bytes = base64.b64decode(encrypted_data)
            key_bytes = base64.b64decode(key)
            
            # Jika IV diberikan secara terpisah
            if iv:
                iv_bytes = base64.b64decode(iv)
                ciphertext_bytes = encrypted_bytes
            else:
                # Jika IV digabungkan dengan ciphertext
                iv_bytes = encrypted_bytes[:16]
                ciphertext_bytes = encrypted_bytes[16:]
            
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            decrypted_padded = cipher.decrypt(ciphertext_bytes)
            decrypted = unpad(decrypted_padded, AES.block_size)
            
            return decrypted.decode()
        except Exception as e:
            return f"Error: {str(e)}"
    
    # =============== ASYMMETRIC KEY METHODS ===============
    
    def generate_rsa_keys(self, key_size=2048):
        """Generate RSA key pair"""
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        self.rsa_key_pair = {
            'private': private_key,
            'public': public_key
        }
        
        return {
            'private_key': private_key.decode(),
            'public_key': public_key.decode()
        }
    
    def rsa_encrypt(self, plaintext, public_key_str=None):
        """Enkripsi dengan RSA"""
        try:
            if public_key_str:
                public_key = RSA.import_key(public_key_str.encode())
            elif self.rsa_key_pair:
                public_key = RSA.import_key(self.rsa_key_pair['public'])
            else:
                return "Error: Tidak ada public key yang tersedia"
            
            cipher = PKCS1_OAEP.new(public_key)
            # RSA memiliki batasan ukuran pesan, jadi kita enkripsi per blok
            # atau gunakan hybrid encryption dalam implementasi nyata
            ciphertext = cipher.encrypt(plaintext.encode())
            
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            return f"Error: {str(e)}"
    
    def rsa_decrypt(self, ciphertext, private_key_str=None):
        """Dekripsi dengan RSA"""
        try:
            if private_key_str:
                private_key = RSA.import_key(private_key_str.encode())
            elif self.rsa_key_pair:
                private_key = RSA.import_key(self.rsa_key_pair['private'])
            else:
                return "Error: Tidak ada private key yang tersedia"
            
            cipher = PKCS1_OAEP.new(private_key)
            ciphertext_bytes = base64.b64decode(ciphertext)
            plaintext = cipher.decrypt(ciphertext_bytes)
            
            return plaintext.decode()
        except Exception as e:
            return f"Error: {str(e)}"
    
    def rsa_sign(self, message, private_key_str=None):
        """Membuat digital signature dengan RSA"""
        try:
            if private_key_str:
                private_key = RSA.import_key(private_key_str.encode())
            elif self.rsa_key_pair:
                private_key = RSA.import_key(self.rsa_key_pair['private'])
            else:
                return "Error: Tidak ada private key yang tersedia"
            
            # Hash pesan
            h = SHA256.new(message.encode())
            # Buat signature
            signature = pkcs1_15.new(private_key).sign(h)
            
            return base64.b64encode(signature).decode()
        except Exception as e:
            return f"Error: {str(e)}"
    
    def rsa_verify(self, message, signature, public_key_str=None):
        """Memverifikasi digital signature dengan RSA"""
        try:
            if public_key_str:
                public_key = RSA.import_key(public_key_str.encode())
            elif self.rsa_key_pair:
                public_key = RSA.import_key(self.rsa_key_pair['public'])
            else:
                return "Error: Tidak ada public key yang tersedia"
            
            # Hash pesan
            h = SHA256.new(message.encode())
            signature_bytes = base64.b64decode(signature)
            
            # Verifikasi signature
            pkcs1_15.new(public_key).verify(h, signature_bytes)
            return "Signature VALID"
        except (ValueError, TypeError):
            return "Signature TIDAK VALID"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def diffie_hellman_demo(self):
        """Simulasi Diffie-Hellman Key Exchange"""
        print("\n--- SIMULASI DIFFIE-HELLMAN KEY EXCHANGE ---")
        
        # Parameter publik (biasanya besar, ini contoh sederhana)
        p = 23  # Prime number
        g = 5   # Generator
        
        print(f"Parameter publik:")
        print(f"  p (prime) = {p}")
        print(f"  g (generator) = {g}")
        
        # Private keys untuk Alice dan Bob
        a = secrets.randbelow(p-1) + 1  # Private key Alice
        b = secrets.randbelow(p-1) + 1  # Private key Bob
        
        print(f"\nPrivate keys (rahasia):")
        print(f"  a (Alice) = {a}")
        print(f"  b (Bob) = {b}")
        
        # Public keys
        A = pow(g, a, p)  # Public key Alice
        B = pow(g, b, p)  # Public key Bob
        
        print(f"\nPublic keys:")
        print(f"  A = g^a mod p = {g}^{a} mod {p} = {A}")
        print(f"  B = g^b mod p = {g}^{b} mod {p} = {B}")
        
        # Shared secret
        s1 = pow(B, a, p)  # Alice menghitung shared secret
        s2 = pow(A, b, p)  # Bob menghitung shared secret
        
        print(f"\nShared secret:")
        print(f"  s (Alice) = B^a mod p = {B}^{a} mod {p} = {s1}")
        print(f"  s (Bob) = A^b mod p = {A}^{b} mod {p} = {s2}")
        
        if s1 == s2:
            print(f"\n✓ Berhasil! Kedua pihak memiliki shared secret yang sama: {s1}")
            # Konversi menjadi kunci AES
            shared_key = hashlib.sha256(str(s1).encode()).digest()[:16]
            print(f"  Kunci AES yang dihasilkan: {base64.b64encode(shared_key).decode()}")
        else:
            print("\n✗ Gagal! Shared secret tidak sama")
        
        return s1
    
    # =============== HASH METHODS ===============
    
    def sha256_hash(self, message):
        """Menghasilkan hash SHA-256"""
        h = SHA256.new(message.encode())
        return h.hexdigest()
    
    def sha512_hash(self, message):
        """Menghasilkan hash SHA-512"""
        h = SHA512.new(message.encode())
        return h.hexdigest()
    
    # =============== CLASSICAL CIPHER METHODS ===============
    
    def shift_cipher(self, text, shift, mode='encrypt'):
        """Shift Cipher (Caesar Cipher)"""
        result = ""
        
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                if mode == 'encrypt':
                    shifted = (ord(char) - ascii_offset + shift) % 26
                else:  # decrypt
                    shifted = (ord(char) - ascii_offset - shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        
        return result
    
    def substitution_cipher(self, text, key, mode='encrypt'):
        """Substitution Cipher"""
        alphabet = string.ascii_lowercase
        result = ""
        
        # Pastikan key valid
        if len(key) != 26 or len(set(key)) != 26:
            return "Error: Key harus berisi 26 karakter unik"
        
        key = key.lower()
        
        for char in text:
            if char.lower() in alphabet:
                idx = alphabet.index(char.lower())
                if mode == 'encrypt':
                    new_char = key[idx]
                else:  # decrypt
                    new_char = alphabet[key.index(char.lower())]
                
                # Pertahankan case asli
                if char.isupper():
                    new_char = new_char.upper()
                result += new_char
            else:
                result += char
        
        return result
    
    def vigenere_cipher(self, text, key, mode='encrypt'):
        """Vigenere Cipher"""
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                key_char = key[key_index % len(key)]
                key_shift = ord(key_char) - ord('A')
                
                if mode == 'encrypt':
                    shifted = (ord(char) - ascii_offset + key_shift) % 26
                else:  # decrypt
                    shifted = (ord(char) - ascii_offset - key_shift) % 26
                
                result += chr(shifted + ascii_offset)
                key_index += 1
            else:
                result += char
        
        return result
    
    def affine_cipher(self, text, a, b, mode='encrypt'):
        """Affine Cipher: E(x) = (ax + b) mod 26"""
        # a harus koprima dengan 26
        if self.gcd(a, 26) != 1:
            return "Error: Nilai a harus koprima dengan 26"
        
        result = ""
        
        for char in text:
            if char.isalpha():
                ascii_offset = ord('A') if char.isupper() else ord('a')
                x = ord(char) - ascii_offset
                
                if mode == 'encrypt':
                    y = (a * x + b) % 26
                else:  # decrypt
                    # Cari invers modular dari a
                    a_inv = self.mod_inverse(a, 26)
                    y = (a_inv * (x - b)) % 26
                
                result += chr(y + ascii_offset)
            else:
                result += char
        
        return result
    
    def hill_cipher(self, text, key_matrix, mode='encrypt'):
        """Hill Cipher"""
        # Pastikan text panjangnya kelipatan dari ukuran matriks
        n = len(key_matrix)
        text = text.upper().replace(" ", "")
        
        # Padding jika diperlukan
        while len(text) % n != 0:
            text += 'X'
        
        # Konversi text ke angka
        nums = [ord(c) - ord('A') for c in text]
        
        # Konversi key_matrix ke numpy array
        key_np = np.array(key_matrix)
        
        if mode == 'decrypt':
            # Cari invers modular dari matriks
            try:
                det = int(np.round(np.linalg.det(key_np)))
                det_inv = self.mod_inverse(det % 26, 26)
                
                # Hitung adjugate matrix
                adj = np.round(np.linalg.inv(key_np) * np.linalg.det(key_np)).astype(int) % 26
                key_np = (det_inv * adj) % 26
            except:
                return "Error: Matriks tidak memiliki invers modular"
        
        result_nums = []
        
        # Proses per blok
        for i in range(0, len(nums), n):
            block = np.array(nums[i:i+n])
            encrypted_block = np.dot(key_np, block) % 26
            result_nums.extend(encrypted_block)
        
        # Konversi angka kembali ke huruf
        result = ''.join([chr(int(num) + ord('A')) for num in result_nums])
        return result
    
    def transposition_cipher(self, text, key, mode='encrypt'):
        """Transposition Cipher"""
        # Hilangkan spasi dan ubah ke uppercase
        text = text.upper().replace(" ", "")
        
        # Buat kunci numerik
        key_order = [(char, i) for i, char in enumerate(key)]
        key_order.sort()
        
        num_cols = len(key)
        num_rows = (len(text) + num_cols - 1) // num_cols
        
        if mode == 'encrypt':
            # Buat matriks
            matrix = []
            for i in range(num_rows):
                row_start = i * num_cols
                row_end = min(row_start + num_cols, len(text))
                row = list(text[row_start:row_end])
                
                # Padding jika diperlukan
                while len(row) < num_cols:
                    row.append('X')
                
                matrix.append(row)
            
            # Baca berdasarkan urutan kolom
            result = ""
            for _, original_idx in key_order:
                for row in matrix:
                    result += row[original_idx]
            
            return result
        
        else:  # decrypt
            # Hitung panjang setiap kolom
            full_rows = len(text) // num_cols
            extra_chars = len(text) % num_cols
            
            col_lengths = [full_rows + 1 if i < extra_chars else full_rows for i in range(num_cols)]
            
            # Rekonstruksi matriks
            matrix = [['' for _ in range(num_cols)] for _ in range(num_rows)]
            
            # Isi matriks kolom demi kolom sesuai urutan kunci
            text_idx = 0
            for _, original_idx in key_order:
                for row_idx in range(col_lengths[original_idx]):
                    matrix[row_idx][original_idx] = text[text_idx]
                    text_idx += 1
            
            # Baca matriks baris demi baris
            result = ""
            for row in matrix:
                result += ''.join(row)
            
            return result.rstrip('X')
    
    # =============== HELPER METHODS ===============
    
    def gcd(self, a, b):
        """Menghitung Greatest Common Divisor"""
        while b != 0:
            a, b = b, a % b
        return a
    
    def mod_inverse(self, a, m):
        """Menghitung invers modular"""
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None
    
    def run(self):
        """Menjalankan program utama"""
        while True:
            self.clear_screen()
            self.display_menu()
            
            main_choice = input("\nMasukkan pilihan (1-5): ")
            
            if main_choice == '1':  # Symmetric Key
                self.handle_symmetric()
            elif main_choice == '2':  # Asymmetric Key
                self.handle_asymmetric()
            elif main_choice == '3':  # Hash Functions
                self.handle_hash()
            elif main_choice == '4':  # Classical Ciphers
                self.handle_classical()
            elif main_choice == '5':  # Exit
                print("\nTerima kasih telah menggunakan Sistem Kriptografi!")
                break
            else:
                print("\nPilihan tidak valid. Silakan coba lagi.")
                input("Tekan Enter untuk melanjutkan...")
    
    def handle_symmetric(self):
        """Handle symmetric cryptography operations"""
        while True:
            self.clear_screen()
            sym_choice = self.symmetric_menu()
            
            if sym_choice in ['1', '2', '3']:
                # Tentukan key size berdasarkan pilihan
                if sym_choice == '1':
                    key_size = 128
                    algo_name = "AES-128"
                elif sym_choice == '2':
                    key_size = 192
                    algo_name = "AES-192"
                else:
                    key_size = 256
                    algo_name = "AES-256"
                
                print(f"\n--- {algo_name} ---")
                print("1. Enkripsi")
                print("2. Dekripsi")
                print("3. Kembali")
                
                op_choice = input("\nPilih operasi (1-3): ")
                
                if op_choice == '1':  # Enkripsi
                    plaintext = input("\nMasukkan plaintext: ")
                    result = self.aes_encrypt(plaintext, key_size)
                    
                    if isinstance(result, dict):
                        print(f"\n✓ Enkripsi berhasil!")
                        print(f"Ciphertext (Base64): {result['ciphertext']}")
                        print(f"Key (Base64): {result['key']}")
                        print(f"IV (Base64): {result['iv']}")
                    else:
                        print(f"\n✗ {result}")
                
                elif op_choice == '2':  # Dekripsi
                    ciphertext = input("\nMasukkan ciphertext (Base64): ")
                    key = input("Masukkan key (Base64): ")
                    iv = input("Masukkan IV (Base64) [kosongkan jika digabung]: ")
                    
                    if iv:
                        result = self.aes_decrypt(ciphertext, key, iv)
                    else:
                        result = self.aes_decrypt(ciphertext, key)
                    
                    print(f"\nPlaintext: {result}")
                
                elif op_choice == '3':  # Kembali
                    continue
                else:
                    print("\nPilihan tidak valid.")
            
            elif sym_choice == '4':  # Kembali
                break
            else:
                print("\nPilihan tidak valid.")
            
            input("\nTekan Enter untuk melanjutkan...")
    
    def handle_asymmetric(self):
        """Handle asymmetric cryptography operations"""
        while True:
            self.clear_screen()
            asym_choice = self.asymmetric_menu()
            
            if asym_choice == '1':  # RSA Encryption/Decryption
                print("\n--- RSA ENCRYPTION/DECRYPTION ---")
                
                # Generate keys jika belum ada
                if not self.rsa_key_pair:
                    print("Generating RSA key pair...")
                    keys = self.generate_rsa_keys()
                    print("\n✓ Key pair berhasil digenerate!")
                    print(f"\nPublic Key:\n{keys['public_key']}")
                    print(f"\nPrivate Key:\n{keys['private_key']}")
                
                print("\n1. Enkripsi")
                print("2. Dekripsi")
                print("3. Generate Key Pair Baru")
                
                op_choice = input("\nPilih operasi (1-3): ")
                
                if op_choice == '1':  # Enkripsi
                    plaintext = input("\nMasukkan plaintext: ")
                    
                    # Tanya apakah menggunakan key sendiri
                    use_custom = input("Gunakan public key sendiri? (y/n): ").lower() == 'y'
                    
                    if use_custom:
                        public_key = input("Masukkan public key: ")
                        result = self.rsa_encrypt(plaintext, public_key)
                    else:
                        result = self.rsa_encrypt(plaintext)
                    
                    print(f"\nCiphertext (Base64): {result}")
                
                elif op_choice == '2':  # Dekripsi
                    ciphertext = input("\nMasukkan ciphertext (Base64): ")
                    
                    # Tanya apakah menggunakan key sendiri
                    use_custom = input("Gunakan private key sendiri? (y/n): ").lower() == 'y'
                    
                    if use_custom:
                        private_key = input("Masukkan private key: ")
                        result = self.rsa_decrypt(ciphertext, private_key)
                    else:
                        result = self.rsa_decrypt(ciphertext)
                    
                    print(f"\nPlaintext: {result}")
                
                elif op_choice == '3':  # Generate baru
                    print("Generating new RSA key pair...")
                    keys = self.generate_rsa_keys()
                    print("\n✓ Key pair berhasil digenerate!")
                    print(f"\nPublic Key:\n{keys['public_key']}")
                    print(f"\nPrivate Key:\n{keys['private_key']}")
            
            elif asym_choice == '2':  # RSA Signature
                print("\n--- RSA DIGITAL SIGNATURE ---")
                
                if not self.rsa_key_pair:
                    print("Generating RSA key pair...")
                    self.generate_rsa_keys()
                
                print("1. Buat Signature")
                print("2. Verifikasi Signature")
                
                op_choice = input("\nPilih operasi (1-2): ")
                
                if op_choice == '1':  # Buat signature
                    message = input("\nMasukkan pesan: ")
                    signature = self.rsa_sign(message)
                    print(f"\nSignature (Base64): {signature}")
                
                elif op_choice == '2':  # Verifikasi signature
                    message = input("\nMasukkan pesan asli: ")
                    signature = input("Masukkan signature (Base64): ")
                    
                    # Tanya apakah menggunakan key sendiri
                    use_custom = input("Gunakan public key sendiri? (y/n): ").lower() == 'y'
                    
                    if use_custom:
                        public_key = input("Masukkan public key: ")
                        result = self.rsa_verify(message, signature, public_key)
                    else:
                        result = self.rsa_verify(message, signature)
                    
                    print(f"\n{result}")
            
            elif asym_choice == '3':  # Diffie-Hellman
                self.diffie_hellman_demo()
            
            elif asym_choice == '4':  # DSA
                print("\n--- DSA (Digital Signature Algorithm) ---")
                print("Catatan: Implementasi DSA lengkap membutuhkan library tambahan.")
                print("RSA Signature sudah menyediakan fungsionalitas serupa.")
                print("Untuk DSA lengkap, gunakan library cryptography atau PyCryptodome.")
            
            elif asym_choice == '5':  # Kembali
                break
            else:
                print("\nPilihan tidak valid.")
            
            input("\nTekan Enter untuk melanjutkan...")
    
    def handle_hash(self):
        """Handle hash function operations"""
        while True:
            self.clear_screen()
            hash_choice = self.hash_menu()
            
            if hash_choice == '1':  # SHA-256
                message = input("\nMasukkan pesan untuk di-hash: ")
                hash_result = self.sha256_hash(message)
                print(f"\nSHA-256 Hash: {hash_result}")
                print(f"Panjang hash: {len(hash_result)} karakter hex")
            
            elif hash_choice == '2':  # SHA-512
                message = input("\nMasukkan pesan untuk di-hash: ")
                hash_result = self.sha512_hash(message)
                print(f"\nSHA-512 Hash: {hash_result}")
                print(f"Panjang hash: {len(hash_result)} karakter hex")
            
            elif hash_choice == '3':  # Kembali
                break
            else:
                print("\nPilihan tidak valid.")
            
            input("\nTekan Enter untuk melanjutkan...")
    
    def handle_classical(self):
        """Handle classical cipher operations"""
        while True:
            self.clear_screen()
            classical_choice = self.classical_menu()
            
            if classical_choice == '1':  # Shift Cipher
                print("\n--- SHIFT CIPHER (CAESAR CIPHER) ---")
                text = input("Masukkan teks: ")
                shift = int(input("Masukkan shift value: "))
                
                print("\n1. Enkripsi")
                print("2. Dekripsi")
                op_choice = input("\nPilih operasi (1-2): ")
                
                if op_choice == '1':
                    result = self.shift_cipher(text, shift, 'encrypt')
                    print(f"\nTeks terenkripsi: {result}")
                elif op_choice == '2':
                    result = self.shift_cipher(text, shift, 'decrypt')
                    print(f"\nTeks terdekripsi: {result}")
            
            elif classical_choice == '2':  # Substitution Cipher
                print("\n--- SUBSTITUTION CIPHER ---")
                print("Key harus 26 karakter unik, contoh: 'zyxwvutsrqponmlkjihgfedcba'")
                text = input("Masukkan teks: ")
                key = input("Masukkan key (26 karakter): ")
                
                print("\n1. Enkripsi")
                print("2. Dekripsi")
                op_choice = input("\nPilih operasi (1-2): ")
                
                if op_choice == '1':
                    result = self.substitution_cipher(text, key, 'encrypt')
                    print(f"\nTeks terenkripsi: {result}")
                elif op_choice == '2':
                    result = self.substitution_cipher(text, key, 'decrypt')
                    print(f"\nTeks terdekripsi: {result}")
            
            elif classical_choice == '3':  # Vigenere Cipher
                print("\n--- VIGENERE CIPHER ---")
                text = input("Masukkan teks: ")
                key = input("Masukkan key: ")
                
                print("\n1. Enkripsi")
                print("2. Dekripsi")
                op_choice = input("\nPilih operasi (1-2): ")
                
                if op_choice == '1':
                    result = self.vigenere_cipher(text, key, 'encrypt')
                    print(f"\nTeks terenkripsi: {result}")
                elif op_choice == '2':
                    result = self.vigenere_cipher(text, key, 'decrypt')
                    print(f"\nTeks terdekripsi: {result}")
            
            elif classical_choice == '4':  # Affine Cipher
                print("\n--- AFFINE CIPHER ---")
                print("Formula: E(x) = (ax + b) mod 26")
                print("a harus koprima dengan 26 (tidak punya faktor persekutuan)")
                text = input("Masukkan teks: ")
                a = int(input("Masukkan nilai a: "))
                b = int(input("Masukkan nilai b: "))
                
                print("\n1. Enkripsi")
                print("2. Dekripsi")
                op_choice = input("\nPilih operasi (1-2): ")
                
                if op_choice == '1':
                    result = self.affine_cipher(text, a, b, 'encrypt')
                    print(f"\nTeks terenkripsi: {result}")
                elif op_choice == '2':
                    result = self.affine_cipher(text, a, b, 'decrypt')
                    print(f"\nTeks terdekripsi: {result}")
            
            elif classical_choice == '5':  # Hill Cipher
                print("\n--- HILL CIPHER ---")
                print("Contoh key matrix 2x2: [[3, 3], [2, 5]]")
                print("Contoh key matrix 3x3: [[6, 24, 1], [13, 16, 10], [20, 17, 15]]")
                text = input("Masukkan teks: ")
                
                n = int(input("Ukuran matriks (2 atau 3): "))
                print(f"Masukkan matriks {n}x{n} (baris per baris):")
                key_matrix = []
                for i in range(n):
                    row = list(map(int, input(f"Baris {i+1}: ").split()))
                    key_matrix.append(row)
                
                print("\n1. Enkripsi")
                print("2. Dekripsi")
                op_choice = input("\nPilih operasi (1-2): ")
                
                if op_choice == '1':
                    result = self.hill_cipher(text, key_matrix, 'encrypt')
                    print(f"\nTeks terenkripsi: {result}")
                elif op_choice == '2':
                    result = self.hill_cipher(text, key_matrix, 'decrypt')
                    print(f"\nTeks terdekripsi: {result}")
            
            elif classical_choice == '6':  # Transposition Cipher
                print("\n--- TRANSPOSITION CIPHER ---")
                text = input("Masukkan teks: ")
                key = input("Masukkan key (contoh: 'KEY'): ")
                
                print("\n1. Enkripsi")
                print("2. Dekripsi")
                op_choice = input("\nPilih operasi (1-2): ")
                
                if op_choice == '1':
                    result = self.transposition_cipher(text, key, 'encrypt')
                    print(f"\nTeks terenkripsi: {result}")
                elif op_choice == '2':
                    result = self.transposition_cipher(text, key, 'decrypt')
                    print(f"\nTeks terdekripsi: {result}")
            
            elif classical_choice == '7':  # Kembali
                break
            else:
                print("\nPilihan tidak valid.")
            
            input("\nTekan Enter untuk melanjutkan...")

# =============== MAIN PROGRAM ===============
if __name__ == "__main__":
    # Instalasi library yang diperlukan
    print("Memeriksa dependensi...")
    print("Pastikan Anda telah menginstal library berikut:")
    print("  pip install pycryptodome numpy sympy")
    print("\nTekan Enter untuk melanjutkan jika library sudah terinstal...")
    input()
    
    try:
        # Coba import library yang diperlukan
        import numpy as np
        from Crypto.Cipher import AES
        from Crypto.PublicKey import RSA
        print("✓ Semua library berhasil diimport!")
    except ImportError as e:
        print(f"\n✗ Error: {e}")
        print("\nSilakan instal library yang diperlukan terlebih dahulu:")
        print("pip install pycryptodome numpy sympy")
        exit(1)
    
    # Jalankan program
    tool = CryptographyTool()
    tool.run()