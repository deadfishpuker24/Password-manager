import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * CryptoUtils.java
 * Handles all cryptographic operations:
 *  - Key derivation from master password using PBKDF2
 *  - AES-256-GCM encryption and decryption
 */
public class CryptoUtils {

    // Algorithm constants
    private static final String KEY_DERIVATION_ALGO = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGO         = "AES/GCM/NoPadding";
    private static final int    KEY_LENGTH_BITS      = 256;
    private static final int    ITERATION_COUNT      = 310_000;   // OWASP 2023 recommendation
    private static final int    SALT_BYTES           = 16;
    private static final int    IV_BYTES             = 12;        // 96-bit IV for GCM
    private static final int    GCM_TAG_BITS         = 128;

    // -----------------------------------------------------------------------
    // Key derivation
    // -----------------------------------------------------------------------

    /** Generate a cryptographically random salt. */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Derive a 256-bit AES key from the master password + salt using PBKDF2.
     *
     * @param masterPassword the user's master password (char[] to allow wiping)
     * @param salt           random salt stored alongside the vault
     * @return a SecretKey suitable for AES-GCM
     */
    public static SecretKey deriveKey(char[] masterPassword, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        PBEKeySpec spec = new PBEKeySpec(masterPassword, salt, ITERATION_COUNT, KEY_LENGTH_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGO);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();   // wipe sensitive data from heap
        }
    }

    // -----------------------------------------------------------------------
    // Encryption / Decryption
    // -----------------------------------------------------------------------

    /**
     * Encrypt plaintext using AES-256-GCM.
     * Output format (all Base64): IV + ":" + ciphertext+authTag
     *
     * @param plaintext the data to encrypt
     * @param key       derived AES key
     * @return Base64-encoded "iv:ciphertext" string
     */
    public static String encrypt(String plaintext, SecretKey key)
            throws GeneralSecurityException {

        byte[] iv = new byte[IV_BYTES];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] cipherBytes = cipher.doFinal(plaintext.getBytes());

        return Base64.getEncoder().encodeToString(iv)
                + ":"
                + Base64.getEncoder().encodeToString(cipherBytes);
    }

    /**
     * Decrypt a ciphertext produced by {@link #encrypt}.
     *
     * @param encryptedData Base64-encoded "iv:ciphertext" string
     * @param key           derived AES key
     * @return original plaintext
     */
    public static String decrypt(String encryptedData, SecretKey key)
            throws GeneralSecurityException {

        String[] parts = encryptedData.split(":", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid encrypted data format.");
        }

        byte[] iv          = Base64.getDecoder().decode(parts[0]);
        byte[] cipherBytes = Base64.getDecoder().decode(parts[1]);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));

        return new String(cipher.doFinal(cipherBytes));
    }

    // -----------------------------------------------------------------------
    // Password hashing (for master password verification)
    // -----------------------------------------------------------------------

    /**
     * Hash the master password with PBKDF2 for storage in the vault header.
     * A fresh random salt is generated; the output is "salt:hash" in Base64.
     */
    public static String hashMasterPassword(char[] masterPassword)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] salt = generateSalt();
        SecretKey key = deriveKey(masterPassword, salt);
        return Base64.getEncoder().encodeToString(salt)
                + ":"
                + Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Verify a master password against a stored "salt:hash" string.
     */
    public static boolean verifyMasterPassword(char[] masterPassword, String storedHash)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        String[] parts = storedHash.split(":", 2);
        byte[] salt        = Base64.getDecoder().decode(parts[0]);
        byte[] expectedKey = Base64.getDecoder().decode(parts[1]);

        SecretKey derived = deriveKey(masterPassword, salt);
        return MessageDigest.isEqual(derived.getEncoded(), expectedKey);
    }
}
