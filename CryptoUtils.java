import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.List;

public class CryptoUtils {

    private static final String KDF_ALGO     = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGO  = "AES/GCM/NoPadding";
    private static final String HMAC_ALGO    = "HmacSHA256";
    private static final int    KEY_BITS     = 256;
    private static final int    ITERATIONS   = 310_000;
    private static final int    SALT_BYTES   = 16;
    private static final int    IV_BYTES     = 12;
    private static final int    GCM_TAG_BITS = 128;

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    public static SecretKey deriveKey(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BITS);
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance(KDF_ALGO);
            return new SecretKeySpec(f.generateSecret(spec).getEncoded(), "AES");
        } finally {
            spec.clearPassword();
        }
    }

    public static String encrypt(String plaintext, SecretKey key)
            throws GeneralSecurityException {
        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        byte[] ct = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(iv)
                + ":" + Base64.getEncoder().encodeToString(ct);
    }

    public static String decrypt(String data, SecretKey key)
            throws GeneralSecurityException {
        String[] parts = data.split(":", 2);
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] ct = Base64.getDecoder().decode(parts[1]);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        return new String(cipher.doFinal(ct));
    }

    public static String hashMasterPassword(char[] pw)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = generateSalt();
        SecretKey k = deriveKey(pw, salt);
        return Base64.getEncoder().encodeToString(salt)
                + ":" + Base64.getEncoder().encodeToString(k.getEncoded());
    }

    public static boolean verifyMasterPassword(char[] pw, String stored)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] p    = stored.split(":", 2);
        byte[]   salt = Base64.getDecoder().decode(p[0]);
        byte[]   exp  = Base64.getDecoder().decode(p[1]);
        return MessageDigest.isEqual(deriveKey(pw, salt).getEncoded(), exp);
    }

    /**
     * Compute HMAC-SHA256 over all credential lines joined together.
     * Used to detect tampering with vault.dat outside the app.
     */
    public static String computeHmac(List<String> lines, SecretKey key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(HMAC_ALGO);
        mac.init(new SecretKeySpec(key.getEncoded(), HMAC_ALGO));
        for (String line : lines) mac.update(line.getBytes());
        return Base64.getEncoder().encodeToString(mac.doFinal());
    }
}