import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/**
 * VaultManager.java
 * Responsible for:
 *  - Creating / loading the encrypted vault file
 *  - Adding, retrieving, listing, and deleting credentials
 *
 * Vault file format (plain text, one line each):
 *   Line 1  : VAULT_VERSION:1
 *   Line 2  : MASTER_HASH:<pbkdf2-salt:pbkdf2-hash>
 *   Line 3  : VAULT_SALT:<base64 salt used to derive the encryption key>
 *   Line 4+ : <serialized Credential lines>
 */
public class VaultManager {

    private static final String VAULT_FILE    = "vault.dat";
    private static final String HEADER_VER    = "VAULT_VERSION:1";
    private static final String PREFIX_HASH   = "MASTER_HASH:";
    private static final String PREFIX_SALT   = "VAULT_SALT:";

    private final Path        vaultPath;
    private       SecretKey   encryptionKey;   // set after successful unlock
    private       String      masterHashLine;  // stored for re-write
    private       String      saltLine;        // stored for re-write
    private final List<Credential> credentials = new ArrayList<>();

    public VaultManager() {
        this.vaultPath = Paths.get(VAULT_FILE);
    }

    // -----------------------------------------------------------------------
    // Vault lifecycle
    // -----------------------------------------------------------------------

    /** @return true if the vault file already exists on disk */
    public boolean vaultExists() {
        return Files.exists(vaultPath);
    }

    /**
     * Create a brand-new vault secured by the given master password.
     */
    public void createVault(char[] masterPassword)
            throws Exception {

        byte[] salt = CryptoUtils.generateSalt();
        encryptionKey  = CryptoUtils.deriveKey(masterPassword, salt);
        masterHashLine = PREFIX_HASH + CryptoUtils.hashMasterPassword(masterPassword);
        saltLine       = PREFIX_SALT + Base64.getEncoder().encodeToString(salt);

        credentials.clear();
        persist();
        System.out.println("[+] New vault created successfully.");
    }

    /**
     * Unlock an existing vault with the master password.
     *
     * @return true on success, false on wrong password
     */
    public boolean unlockVault(char[] masterPassword) throws Exception {
        List<String> lines = Files.readAllLines(vaultPath);
        if (lines.size() < 3 || !lines.get(0).equals(HEADER_VER)) {
            throw new IOException("Vault file is corrupted or unrecognised.");
        }

        masterHashLine = lines.get(1);
        saltLine       = lines.get(2);

        String storedHash = masterHashLine.substring(PREFIX_HASH.length());
        if (!CryptoUtils.verifyMasterPassword(masterPassword, storedHash)) {
            return false;   // wrong password
        }

        byte[] salt = Base64.getDecoder().decode(saltLine.substring(PREFIX_SALT.length()));
        encryptionKey = CryptoUtils.deriveKey(masterPassword, salt);

        // Load credentials
        credentials.clear();
        for (int i = 3; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (!line.isEmpty()) {
                credentials.add(Credential.deserialize(line));
            }
        }
        return true;
    }

    // -----------------------------------------------------------------------
    // Credential operations
    // -----------------------------------------------------------------------

    /** Encrypt and store a new credential. */
    public void addCredential(String site, String username, String plainPassword)
            throws Exception {
        requireUnlocked();
        String encrypted = CryptoUtils.encrypt(plainPassword, encryptionKey);
        credentials.add(new Credential(site, username, encrypted));
        persist();
        System.out.println("[+] Credential saved for: " + site);
    }

    /**
     * Retrieve and decrypt the password for a given site.
     *
     * @return the plaintext password, or null if not found
     */
    public String getPassword(String site) throws Exception {
        requireUnlocked();
        for (Credential c : credentials) {
            if (c.getSiteName().equalsIgnoreCase(site)) {
                return CryptoUtils.decrypt(c.getEncryptedPassword(), encryptionKey);
            }
        }
        return null;
    }

    /** List all stored sites with their usernames (passwords NOT shown). */
    public void listCredentials() {
        requireUnlocked();
        if (credentials.isEmpty()) {
            System.out.println("  (no credentials stored yet)");
            return;
        }
        System.out.println();
        for (int i = 0; i < credentials.size(); i++) {
            System.out.printf("[%d]%n%s%n", i + 1, credentials.get(i));
        }
    }

    /** Delete the credential for a given site. */
    public boolean deleteCredential(String site) throws Exception {
        requireUnlocked();
        boolean removed = credentials.removeIf(
                c -> c.getSiteName().equalsIgnoreCase(site));
        if (removed) persist();
        return removed;
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    private void persist() throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add(HEADER_VER);
        lines.add(masterHashLine);
        lines.add(saltLine);
        for (Credential c : credentials) {
            lines.add(c.serialize());
        }
        Files.write(vaultPath, lines,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void requireUnlocked() {
        if (encryptionKey == null) {
            throw new IllegalStateException("Vault is locked. Please unlock first.");
        }
    }

    /** Wipe the encryption key from memory on exit. */
    public void lock() {
        encryptionKey = null;
        credentials.clear();
    }
}
