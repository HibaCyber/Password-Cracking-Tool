import hashlib
import itertools
import string
import time
from typing import List, Optional


class PasswordCracker:
    def __init__(self, hash_algorithm: str = "sha256"):
        self.hash_algorithm = hash_algorithm

    def hash_password(self, password: str) -> str:
        """Return the hash of a given password."""
        hash_func = hashlib.new(self.hash_algorithm)
        hash_func.update(password.encode())
        return hash_func.hexdigest()

    def dictionary_attack(self, hash_to_crack: str, wordlist: List[str]) -> Optional[str]:
        """Try cracking the hash using a dictionary attack."""
        print("[*] Starting dictionary attack...")
        start_time = time.time()

        for word in wordlist:
            word = word.strip()
            if self.hash_password(word) == hash_to_crack:
                print(f"[+] Match found in {time.time() - start_time:.2f} seconds")
                return word

        print("[-] Dictionary attack failed.")
        return None

    def brute_force_attack(
        self, hash_to_crack: str, charset: str = string.ascii_lowercase + string.digits, max_length: int = 4
    ) -> Optional[str]:
        """Try cracking the hash using brute-force attack (length-limited)."""
        print(f"[*] Starting brute-force attack (max length={max_length})...")
        start_time = time.time()

        for length in range(1, max_length + 1):
            for guess_tuple in itertools.product(charset, repeat=length):
                guess = ''.join(guess_tuple)
                if self.hash_password(guess) == hash_to_crack:
                    print(f"[+] Match found in {time.time() - start_time:.2f} seconds")
                    return guess

        print("[-] Brute-force attack failed.")
        return None

if __name__ == "__main__":
    cracker = PasswordCracker("sha256")

    # Create a hash of a known password (for testing)
    target_password = "abc123"
    target_hash = cracker.hash_password(target_password)
    print(f"[*] Target password hash: {target_hash}")

    # Dictionary attack
    dictionary = ["password", "123456", "qwerty", "letmein", "abc123"]
    found_password = cracker.dictionary_attack(target_hash, dictionary)
    if found_password:
        print(f"[SUCCESS] Dictionary attack cracked password: {found_password}\n")

    # Brute-force attack
    found_password = cracker.brute_force_attack(target_hash, max_length=6)
    if found_password:
        print(f"[SUCCESS] Brute-force cracked password: {found_password}")

