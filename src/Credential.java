/**
 * Credential.java
 * Immutable value object representing a single stored credential.
 * The password field is stored ENCRYPTED at all times.
 */
public class Credential {

    private final String siteName;       // e.g. "github.com"
    private final String username;       // stored in plaintext (not sensitive)
    private final String encryptedPassword; // AES-GCM encrypted password

    public Credential(String siteName, String username, String encryptedPassword) {
        this.siteName          = siteName;
        this.username          = username;
        this.encryptedPassword = encryptedPassword;
    }

    public String getSiteName()           { return siteName; }
    public String getUsername()           { return username; }
    public String getEncryptedPassword()  { return encryptedPassword; }

    /**
     * Serialize to a single pipe-delimited line for file storage.
     * Format:  siteName|username|encryptedPassword
     */
    public String serialize() {
        return siteName + "|" + username + "|" + encryptedPassword;
    }

    /**
     * Reconstruct a Credential from a serialized line.
     */
    public static Credential deserialize(String line) {
        String[] parts = line.split("\\|", 3);
        if (parts.length != 3) {
            throw new IllegalArgumentException("Corrupted credential line: " + line);
        }
        return new Credential(parts[0], parts[1], parts[2]);
    }

    @Override
    public String toString() {
        return String.format("  Site     : %s%n  Username : %s", siteName, username);
    }
}
