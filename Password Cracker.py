import hashlib
import itertools
import string
import time
from typing import List, Optional


class PasswordCracker:
    def __init__(self, hash_algorithm: str = "sha256", verbose: bool = False):
        self.hash_algorithm = hash_algorithm
        self.verbose = verbose

    def hash_password(self, password: str, salt: str = "") -> str:
        """Return the hash of a given password (with optional salt)."""
        hash_func = hashlib.new(self.hash_algorithm)
        hash_func.update((salt + password).encode())
        return hash_func.hexdigest()

    def dictionary_attack(self, hash_to_crack: str, wordlist: List[str], salt: str = "") -> Optional[str]:
        """Try cracking the hash using a dictionary attack."""
        print("\n[*] Starting dictionary attack...")
        start_time = time.time()
        attempts = 0

        for word in wordlist:
            word = word.strip()
            attempts += 1
            guess_hash = self.hash_password(word, salt)
            if self.verbose:
                print(f"Trying: {word} -> {guess_hash}")
            if guess_hash == hash_to_crack:
                print(f"[+] Match found: '{word}' in {time.time() - start_time:.2f}s ({attempts} attempts)")
                return word

        print(f"[-] Dictionary attack failed after {attempts} attempts.")
        return None

    def brute_force_attack(
        self, hash_to_crack: str, charset: str = string.ascii_lowercase + string.digits,
        max_length: int = 4, salt: str = ""
    ) -> Optional[str]:
        """Try cracking the hash using brute-force attack (length-limited)."""
        print(f"\n[*] Starting brute-force attack (charset size={len(charset)}, max length={max_length})...")
        start_time = time.time()
        attempts = 0

        for length in range(1, max_length + 1):
            for guess_tuple in itertools.product(charset, repeat=length):
                guess = ''.join(guess_tuple)
                attempts += 1
                guess_hash = self.hash_password(guess, salt)
                if self.verbose and attempts % 10000 == 0:  # print every 10k tries
                    print(f"Trying: {guess}")
                if guess_hash == hash_to_crack:
                    print(f"[+] Match found: '{guess}' in {time.time() - start_time:.2f}s ({attempts} attempts)")
                    return guess

        print(f"[-] Brute-force attack failed after {attempts} attempts.")
        return None

    def hybrid_attack(self, hash_to_crack: str, wordlist: List[str], suffix_charset=string.digits, max_suffix_len=2, salt: str = "") -> Optional[str]:
        """Dictionary + small brute-force on top (hybrid attack)."""
        print("\n[*] Starting hybrid attack...")
        start_time = time.time()
        attempts = 0

        for word in wordlist:
            word = word.strip()
            for length in range(max_suffix_len + 1):
                for suffix in itertools.product(suffix_charset, repeat=length):
                    candidate = word + ''.join(suffix)
                    attempts += 1
                    guess_hash = self.hash_password(candidate, salt)
                    if self.verbose:
                        print(f"Trying: {candidate}")
                    if guess_hash == hash_to_crack:
                        print(f"[+] Match found: '{candidate}' in {time.time() - start_time:.2f}s ({attempts} attempts)")
                        return candidate

        print(f"[-] Hybrid attack failed after {attempts} attempts.")
        return None


def load_wordlist_from_file(filepath: str) -> List[str]:
    """Load a wordlist from a file into a list of words."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            words = f.readlines()
        print(f"[*] Loaded {len(words)} words from {filepath}")
        return words
    except FileNotFoundError:
        print(f"[-] Wordlist file not found: {filepath}")
        return []


if __name__ == "__main__":
    # === CONFIGURATION ===
    target_password = "abc123"    # known password (for testing)
    hash_algorithm = "sha256"     # choose: md5, sha1, sha256, sha512
    salt = "xyz"                  # optional salt, set "" if not used
    verbose_mode = False          # set True to see detailed attempts

    cracker = PasswordCracker(hash_algorithm, verbose=verbose_mode)
    target_hash = cracker.hash_password(target_password, salt)

    print("="*60)
    print(" 🔐 Advanced Password Cracker 🔐")
    print("="*60)
    print(f"[*] Target password hash ({hash_algorithm}, salt='{salt}'): {target_hash}\n")

    # === MENU ===
    print("Choose attack method:")
    print("1. Dictionary Attack (default small wordlist)")
    print("2. Dictionary Attack (custom file wordlist)")
    print("3. Brute Force Attack")
    print("4. Hybrid Attack (dictionary + suffixes)")

    choice = input("\nEnter choice (1/2/3/4): ").strip()

    if choice == "1":
        wordlist = ["password", "123456", "qwerty", "letmein", "abc123", "admin", "welcome"]
        found = cracker.dictionary_attack(target_hash, wordlist, salt)
        if found:
            print(f"[SUCCESS] Dictionary cracked password: {found}")
    elif choice == "2":
        filepath = input("Enter wordlist file path: ").strip()
        wordlist = load_wordlist_from_file(filepath)
        if wordlist:
            found = cracker.dictionary_attack(target_hash, wordlist, salt)
            if found:
                print(f"[SUCCESS] Dictionary cracked password: {found}")
    elif choice == "3":
        max_len = int(input("Enter maximum password length (e.g., 4-6): "))
        charset_choice = input("Choose charset: [1] lowercase [2] digits [3] lowercase+digits [4] full ascii: ").strip()
        if charset_choice == "1":
            charset = string.ascii_lowercase
        elif charset_choice == "2":
            charset = string.digits
        elif charset_choice == "3":
            charset = string.ascii_lowercase + string.digits
        else:
            charset = string.ascii_letters + string.digits + string.punctuation

        found = cracker.brute_force_attack(target_hash, charset, max_length=max_len, salt=salt)
        if found:
            print(f"[SUCCESS] Brute-force cracked password: {found}")
    elif choice == "4":
        wordlist = ["password", "hello", "admin", "test", "abc"]
        found = cracker.hybrid_attack(target_hash, wordlist, salt=salt)
        if found:
            print(f"[SUCCESS] Hybrid cracked password: {found}")
    else:
        print("[-] Invalid choice. Exiting...")

    print("\n[*] Program finished.")
