import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

/*
 * Software Security (SDEV 4303) - Chapter 2 - Programming Task (part 2)
 * Student: Mahmoud Basel AL-Juaidi   ID: 120230589
 *
 * The same idea, but this time using Java's own security library
 * (KeyPairGenerator + Signature "SHA256withRSA").
 * This is how it is done in real programs.
 */
public class JavaBuiltInSignature {

    public static void main(String[] args) throws Exception {
        System.out.println("===========================================");
        System.out.println("  RSA Signature using Java Security API");
        System.out.println("===========================================");

        // 1) make the key pair (2048 bits)
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        System.out.println("\n[1] Key pair generated (2048-bit).");
        System.out.println("Public key (Base64, first 60 chars): "
                + Base64.getEncoder().encodeToString(keys.getPublic().getEncoded()).substring(0, 60) + "...");

        String message = "Transfer $1000 to Mark";
        System.out.println("\n[2] Message: " + message);

        // 2) Alice signs with her PRIVATE key
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keys.getPrivate());
        signer.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = signer.sign();
        System.out.println("\n[3] Signature (Base64, first 60 chars): "
                + Base64.getEncoder().encodeToString(signature).substring(0, 60) + "...");
        System.out.println("    Signature length = " + signature.length + " bytes");

        // 3) Bob verifies with Alice's PUBLIC key
        System.out.println("\n[4] Verify original message: "
                + (check(message, signature, keys) ? "VALID" : "INVALID"));

        // 4) Oscar changes the name in the message
        String changed = "Transfer $1000 to Oscar";
        System.out.println("[5] Verify changed message \"" + changed + "\": "
                + (check(changed, signature, keys) ? "VALID" : "INVALID"));
    }

    static boolean check(String message, byte[] signature, KeyPair keys) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(keys.getPublic());
        verifier.update(message.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signature);
    }
}
