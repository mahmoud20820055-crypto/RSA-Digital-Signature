# RSA Digital Signature in Java

**Software Security (SDEV 4303) – Chapter 2: Cryptographic Tools – Programming Task**
**Student:** Mahmoud Basel AL-Juaidi – **ID:** 120230589
**Teacher:** Dr. Abdelkareem Alashqar – Islamic University of Gaza – 2026/2027

## What is inside

| File | What it does |
|------|--------------|
| `src/RSADigitalSignature.java` | RSA signature written by hand with `BigInteger` (key generation, SHA-256 hash, sign, verify, and two tampering tests). |
| `src/JavaBuiltInSignature.java` | The same thing using Java's built-in `Signature` class (`SHA256withRSA`). |
| `screenshots/` | Screenshots of the program output. |

## How it works (short)

1. Pick two big primes `p` and `q`, then `n = p*q` and `phi = (p-1)(q-1)`.
2. Public key: `e = 65537`. Private key: `d = e^-1 mod phi`.
3. **Sign:** `S = H(M)^d mod n` (needs the private key).
4. **Verify:** compute `S^e mod n` and compare it with `H(M)` (needs only the public key).

If someone changes the message or the signature, the two hashes don't match, so the signature is **INVALID**.

## How to run

```bash
javac -d out src/*.java
java -cp out RSADigitalSignature
java -cp out JavaBuiltInSignature
```

Requires JDK 8 or newer (no extra libraries).
