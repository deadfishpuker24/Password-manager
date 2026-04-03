import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class VaultManager {

    private static final String VAULT_FILE  = "vault.dat";
    private static final String AUDIT_FILE  = "audit.log";
    private static final String HEADER      = "VAULT_VERSION:1";
    private static final String PFX_HASH    = "MASTER_HASH:";
    private static final String PFX_SALT    = "VAULT_SALT:";
    private static final String HMAC_PREFIX = "VAULT_HMAC:";
    private static final DateTimeFormatter DT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private SecretKey              encKey;
    private String                 masterHashLine;
    private String                 saltLine;
    private final List<Credential> credentials = new ArrayList<>();

    public boolean vaultExists() {
        return Files.exists(Paths.get(VAULT_FILE));
    }

    public void createVault(char[] pw) throws Exception {
        byte[] salt = CryptoUtils.generateSalt();
        String hash = CryptoUtils.hashMasterPassword(pw);
        List<String> lines = new ArrayList<>();
        lines.add(HEADER);
        lines.add(PFX_HASH + hash);
        lines.add(PFX_SALT + Base64.getEncoder().encodeToString(salt));
        Files.write(Paths.get(VAULT_FILE), lines,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        System.out.println("[+] Vault created.");
        unlock(pw);
    }

    public boolean unlock(char[] pw) throws Exception {
        // --- Integrity check ---
        List<String> lines = Files.readAllLines(Paths.get(VAULT_FILE));
        if (lines.size() < 3 || !lines.get(0).equals(HEADER)) return false;

        String storedHash = lines.get(1).substring(PFX_HASH.length());
        if (!CryptoUtils.verifyMasterPassword(pw, storedHash)) {
            logAudit("FAILED login attempt");
            return false;
        }

        masterHashLine = lines.get(1);
        saltLine       = lines.get(2);
        byte[] salt    = Base64.getDecoder().decode(saltLine.substring(PFX_SALT.length()));
        encKey         = CryptoUtils.deriveKey(pw, salt);

        // Verify HMAC if present
        int dataStart = 3;
        if (lines.size() > 3 && lines.get(3).startsWith(HMAC_PREFIX)) {
            String storedHmac = lines.get(3).substring(HMAC_PREFIX.length());
            String computedHmac = CryptoUtils.computeHmac(getCredentialLines(lines, 4), encKey);
            if (!storedHmac.equals(computedHmac)) {
                logAudit("TAMPER DETECTED - vault integrity check failed");
                System.out.println("[!] WARNING: Vault file may have been tampered with!");
                return false;
            }
            dataStart = 4;
        }

        credentials.clear();
        for (int i = dataStart; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (!line.isEmpty()) credentials.add(Credential.deserialize(line));
        }
        logAudit("Successful unlock");
        return true;
    }

    public void lock() {
        encKey = null;
        credentials.clear();
    }

    public void addCredential(String site, String username, String plainPw) throws Exception {
        requireUnlocked();
        credentials.add(new Credential(site, username, CryptoUtils.encrypt(plainPw, encKey)));
        persist();
        System.out.println("[+] Credential saved for: " + site);
    }

    /**
     * Returns all credentials matching the site name.
     */
    public List<Credential> getCredentialsForSite(String site) {
        requireUnlocked();
        List<Credential> matches = new ArrayList<>();
        for (Credential c : credentials)
            if (c.getSiteName().equalsIgnoreCase(site)) matches.add(c);
        return matches;
    }

    public String decryptPassword(Credential c) throws Exception {
        requireUnlocked();
        return CryptoUtils.decrypt(c.getEncryptedPassword(), encKey);
    }

    public void listCredentials() {
        requireUnlocked();
        if (credentials.isEmpty()) { System.out.println("  (no credentials stored)"); return; }
        System.out.println();
        for (int i = 0; i < credentials.size(); i++)
            System.out.printf("[%d]%n%s%n%n", i + 1, credentials.get(i));
    }

    public boolean deleteCredential(String site, String username) throws Exception {
        requireUnlocked();
        boolean removed = credentials.removeIf(c ->
                c.getSiteName().equalsIgnoreCase(site) &&
                c.getUsername().equalsIgnoreCase(username));
        if (removed) persist();
        return removed;
    }

    // -----------------------------------------------------------------------
    // Audit log
    // -----------------------------------------------------------------------

    private void logAudit(String event) {
        try {
            String entry = "[" + LocalDateTime.now().format(DT) + "] " + event + "\n";
            Files.writeString(Paths.get(AUDIT_FILE), entry,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {}
    }

    // -----------------------------------------------------------------------
    // Persistence + HMAC
    // -----------------------------------------------------------------------

    private void persist() throws Exception {
        List<String> credLines = new ArrayList<>();
        for (Credential c : credentials) credLines.add(c.serialize());

        String hmac = CryptoUtils.computeHmac(credLines, encKey);

        List<String> lines = new ArrayList<>();
        lines.add(HEADER);
        lines.add(masterHashLine);
        lines.add(saltLine);
        lines.add(HMAC_PREFIX + hmac);
        lines.addAll(credLines);

        Files.write(Paths.get(VAULT_FILE), lines,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private List<String> getCredentialLines(List<String> all, int from) {
        List<String> result = new ArrayList<>();
        for (int i = from; i < all.size(); i++) {
            String l = all.get(i).trim();
            if (!l.isEmpty()) result.add(l);
        }
        return result;
    }

    private void requireUnlocked() {
        if (encKey == null) throw new IllegalStateException("Vault is locked.");
    }
}