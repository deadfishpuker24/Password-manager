/**
 * Credential.java
 * Immutable data object representing one stored credential.
 * The password field is always stored encrypted — never plaintext.
 *
 * Serialization format (pipe-delimited, one line in vault file):
 *   siteName|username|encryptedPassword
 */
public class Credential {

    private final String siteName;
    private final String username;
    private final String encryptedPassword;

    public Credential(String siteName, String username, String encryptedPassword) {
        this.siteName          = siteName;
        this.username          = username;
        this.encryptedPassword = encryptedPassword;
    }

    public String getSiteName()           { return siteName; }
    public String getUsername()           { return username; }
    public String getEncryptedPassword()  { return encryptedPassword; }

    /** Serialize to a single line for file storage. */
    public String serialize() {
        return siteName + "|" + username + "|" + encryptedPassword;
    }

    /** Rebuild a Credential from a serialized line. */
    public static Credential deserialize(String line) {
        String[] p = line.split("\\|", 3);
        if (p.length != 3) throw new IllegalArgumentException("Corrupted line: " + line);
        return new Credential(p[0], p[1], p[2]);
    }

    @Override
    public String toString() {
        return String.format("  Site     : %s%n  Username : %s", siteName, username);
    }
}