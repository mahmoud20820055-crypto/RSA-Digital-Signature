import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Scanner;

/*
 * Software Security (SDEV 4303) - Chapter 2 - Programming Task
 * Student: Mahmoud Basel AL-Juaidi   ID: 120230589
 *
 * RSA Digital Signature (written by hand using BigInteger).
 *
 * The idea in simple words:
 *   1) Make an RSA key pair (public key = e,n  and  private key = d,n).
 *   2) Hash the message with SHA-256.
 *   3) Sign:   signature = hash ^ d mod n   (only the owner of d can do this)
 *   4) Verify: hash2 = signature ^ e mod n  (anyone with the public key can do this)
 *      If hash2 equals the hash of the message we got -> signature is valid.
 */
public class RSADigitalSignature {

    // the keys
    static BigInteger n;   // modulus (part of both keys)
    static BigInteger e;   // public exponent
    static BigInteger d;   // private exponent (secret!)

    public static void main(String[] args) throws Exception {
        Scanner input = new Scanner(System.in);

        System.out.println("===========================================");
        System.out.println("     RSA Digital Signature - Java Demo");
        System.out.println("  Mahmoud Basel AL-Juaidi - 120230589");
        System.out.println("===========================================");

        // Step 1: generate the keys
        System.out.println("\n[Step 1] Generating RSA keys (1024-bit)...");
        generateKeys(1024);
        System.out.println("Public key  e = " + e);
        System.out.println("Public key  n = " + shortText(n));
        System.out.println("Private key d = " + shortText(d));

        // Step 2: read the message from the user
        System.out.print("\n[Step 2] Enter the message you want to sign: ");
        String message = input.nextLine();

        // Step 3: hash the message
        BigInteger hash = hashMessage(message);
        System.out.println("\n[Step 3] SHA-256 hash of the message:");
        System.out.println(hash.toString(16));

        // Step 4: sign the hash with the private key
        BigInteger signature = sign(hash);
        System.out.println("\n[Step 4] Signature (hash ^ d mod n):");
        System.out.println(shortText(signature));

        // Step 5: verify with the public key (the original message)
        System.out.println("\n[Step 5] Bob verifies the ORIGINAL message...");
        boolean ok = verify(message, signature);
        printResult(ok);

        // Step 6: someone changes the message (attack test)
        System.out.print("\n[Step 6] Enter a modified message (to test tampering): ");
        String fakeMessage = input.nextLine();
        System.out.println("Bob verifies the MODIFIED message with the same signature...");
        boolean ok2 = verify(fakeMessage, signature);
        printResult(ok2);

        // Step 7: someone changes the signature itself
        System.out.println("\n[Step 7] Changing the signature by adding 1 to it...");
        BigInteger fakeSignature = signature.add(BigInteger.ONE);
        boolean ok3 = verify(message, fakeSignature);
        printResult(ok3);

        System.out.println("\nDone.");
        input.close();
    }

    // generate p, q, n, phi, e and d
    static void generateKeys(int bits) {
        SecureRandom random = new SecureRandom();

        // two big random prime numbers
        BigInteger p = BigInteger.probablePrime(bits / 2, random);
        BigInteger q = BigInteger.probablePrime(bits / 2, random);

        n = p.multiply(q);

        // phi = (p-1)(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // 65537 is the common value for e
        e = new BigInteger("65537");

        // e must not share a factor with phi, if it does we try again
        while (!phi.gcd(e).equals(BigInteger.ONE)) {
            p = BigInteger.probablePrime(bits / 2, random);
            q = BigInteger.probablePrime(bits / 2, random);
            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        }

        // d is the inverse of e mod phi  ->  (e * d) mod phi = 1
        d = e.modInverse(phi);
    }

    // SHA-256 hash of the message, turned into a positive number
    static BigInteger hashMessage(String message) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(message.getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, hashBytes);
    }

    // signing uses the PRIVATE key d
    static BigInteger sign(BigInteger hash) {
        return hash.modPow(d, n);
    }

    // verifying uses the PUBLIC key e
    static boolean verify(String message, BigInteger signature) throws Exception {
        BigInteger hashFromMessage = hashMessage(message);
        BigInteger hashFromSignature = signature.modPow(e, n);

        System.out.println("  hash of received message : " + hashFromMessage.toString(16));
        System.out.println("  hash from signature      : " + hashFromSignature.toString(16));

        return hashFromMessage.equals(hashFromSignature);
    }

    static void printResult(boolean valid) {
        if (valid) {
            System.out.println("  Result: VALID signature :)  -> message is from the sender and not changed");
        } else {
            System.out.println("  Result: INVALID signature :(  -> message or signature was changed!");
        }
    }

    // the numbers are very long, so I only print the start and the end
    static String shortText(BigInteger number) {
        String s = number.toString();
        if (s.length() <= 40) return s;
        return s.substring(0, 20) + "..." + s.substring(s.length() - 20) + "  (" + s.length() + " digits)";
    }
}
