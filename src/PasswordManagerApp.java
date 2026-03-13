import java.io.Console;
import java.util.Arrays;
import java.util.Scanner;

/**
 * PasswordManagerApp.java
 * Console-based entry point.
 *
 * Menu:
 *   1. Add credential
 *   2. Retrieve password
 *   3. List all sites
 *   4. Delete credential
 *   0. Exit (locks vault & wipes key from memory)
 */
public class PasswordManagerApp {

    private static final VaultManager vault  = new VaultManager();
    private static final Scanner       input  = new Scanner(System.in);

    public static void main(String[] args) {
        printBanner();

        try {
            if (!vault.vaultExists()) {
                setupNewVault();
            } else {
                if (!unlockExistingVault()) {
                    System.out.println("[-] Too many failed attempts. Exiting.");
                    return;
                }
            }

            runMainMenu();

        } catch (Exception e) {
            System.err.println("[!] Unexpected error: " + e.getMessage());
        } finally {
            vault.lock();
            System.out.println("\n[*] Vault locked. Goodbye.");
        }
    }

    // -----------------------------------------------------------------------
    // Setup / unlock
    // -----------------------------------------------------------------------

    private static void setupNewVault() throws Exception {
        System.out.println("[*] No vault found. Creating a new one.");
        char[] pw1 = readPassword("    Enter master password  : ");
        char[] pw2 = readPassword("    Confirm master password: ");

        if (!Arrays.equals(pw1, pw2)) {
            Arrays.fill(pw1, '\0');
            Arrays.fill(pw2, '\0');
            System.out.println("[-] Passwords do not match. Exiting.");
            System.exit(1);
        }

        vault.createVault(pw1);
        Arrays.fill(pw1, '\0');
        Arrays.fill(pw2, '\0');
    }

    private static boolean unlockExistingVault() throws Exception {
        System.out.println("[*] Vault found. Please authenticate.");
        for (int attempt = 1; attempt <= 3; attempt++) {
            char[] pw = readPassword("    Master password (attempt " + attempt + "/3): ");
            if (vault.unlockVault(pw)) {
                Arrays.fill(pw, '\0');
                System.out.println("[+] Vault unlocked successfully.\n");
                return true;
            }
            Arrays.fill(pw, '\0');
            System.out.println("[-] Incorrect password.");
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Main menu
    // -----------------------------------------------------------------------

    private static void runMainMenu() throws Exception {
        boolean running = true;
        while (running) {
            printMenu();
            String choice = input.nextLine().trim();
            System.out.println();

            switch (choice) {
                case "1" -> addCredential();
                case "2" -> retrievePassword();
                case "3" -> listCredentials();
                case "4" -> deleteCredential();
                case "0" -> running = false;
                default  -> System.out.println("[!] Invalid option.");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Menu actions
    // -----------------------------------------------------------------------

    private static void addCredential() throws Exception {
        System.out.print("  Site name : ");
        String site = input.nextLine().trim();
        System.out.print("  Username  : ");
        String user = input.nextLine().trim();
        char[] pw   = readPassword("  Password  : ");

        vault.addCredential(site, user, new String(pw));
        Arrays.fill(pw, '\0');
    }

    private static void retrievePassword() throws Exception {
        System.out.print("  Site name: ");
        String site = input.nextLine().trim();
        String pw   = vault.getPassword(site);

        if (pw == null) {
            System.out.println("[-] No credential found for: " + site);
        } else {
            System.out.println("[+] Password for " + site + ": " + pw);
            System.out.println("    (clear your terminal after use)");
        }
    }

    private static void listCredentials() {
        System.out.println("--- Stored Credentials ---");
        vault.listCredentials();
    }

    private static void deleteCredential() throws Exception {
        System.out.print("  Site name to delete: ");
        String site = input.nextLine().trim();
        if (vault.deleteCredential(site)) {
            System.out.println("[+] Deleted credential for: " + site);
        } else {
            System.out.println("[-] No credential found for: " + site);
        }
    }

    // -----------------------------------------------------------------------
    // UI helpers
    // -----------------------------------------------------------------------

    private static void printBanner() {
        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║    AES-256 Password Manager v1.0     ║");
        System.out.println("║    PBKDF2 + GCM  |  Honours Project  ║");
        System.out.println("╚══════════════════════════════════════╝");
        System.out.println();
    }

    private static void printMenu() {
        System.out.println("┌─────────────────────────┐");
        System.out.println("│  1. Add credential      │");
        System.out.println("│  2. Retrieve password   │");
        System.out.println("│  3. List all sites      │");
        System.out.println("│  4. Delete credential   │");
        System.out.println("│  0. Exit & lock vault   │");
        System.out.println("└─────────────────────────┘");
        System.out.print("Choice: ");
    }

    /**
     * Read a password securely using Console (hides input) or Scanner fallback.
     */
    private static char[] readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        }
        // IDE fallback (input visible — acceptable for dev/testing only)
        System.out.print(prompt + "[IDE mode - input visible] ");
        return input.nextLine().toCharArray();
    }
}
