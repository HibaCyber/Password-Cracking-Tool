Educational Password Cracking Tool (SHA-256) 🔐

A simple educational password cracking tool written in Python that demonstrates two classical attack techniques used to evaluate password strength:
Dictionary attack — testing a list of likely passwords (a wordlist) by hashing each and comparing to a target hash.
Brute-force attack (tiny demo) — exhaustively trying all combinations from a very small charset and length to show how quickly complexity grows.

Critical — For educational use only.
Use this tool only on accounts, hashes, or systems you own or where you have explicit written permission to test. Unauthorized password cracking or access is illegal and unethical. This project exists to teach why strong, unique passwords and proper hashing/salting are essential.

*Overview*

This repository is intended for learners who want to understand:
How hashed passwords are verified (one-way hashing).
Why dictionary lists and brute-force can recover weak passwords.
How password complexity (length, charset) drastically increases the computational cost for attackers.
The importance of using salts, pepper, and slow hashing algorithms (bcrypt/argon2) instead of fast hashes like SHA-256 for password storage.
The tool intentionally keeps the brute-force demo tiny (very small charset / length) to make it safe and fast on ordinary machines.

*Features*

Demonstrates a dictionary attack against a SHA-256 hash using a user-supplied wordlist.
Demonstrates a tiny brute-force example with configurable charset and maximum length (kept small by default).
Prints progress and timing so learners can see how long operations take.
Safe-by-default: requires explicit confirmation, small default search space, and repeated ethical warnings.
Optional export of results and timing metrics for study and reporting.

Extensible for classroom exercises and labs (e.g., demonstrate salted vs unsalted hashing).
