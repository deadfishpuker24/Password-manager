import java.io.Console;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class PasswordManagerApp {

    private static final VaultManager vault = new VaultManager();
    private static final Scanner      input = new Scanner(System.in);

    public static void main(String[] args) {
        printBanner();
        try {
            if (!vault.vaultExists()) {
                setupNewVault();
            } else {
                if (!unlockVault()) {
                    System.out.println("[-] Too many failed attempts. Exiting.");
                    return;
                }
            }
            runMenu();
        } catch (Exception e) {
            System.err.println("[!] Error: " + e.getMessage());
        } finally {
            vault.lock();
            System.out.println("\n[*] Vault locked. Goodbye.");
        }
    }

    private static void setupNewVault() throws Exception {
        System.out.println("[*] First run — creating vault.\n");
        char[] pw1 = readPassword("    Set master password : ");
        char[] pw2 = readPassword("    Confirm password   : ");
        if (!Arrays.equals(pw1, pw2)) {
            System.out.println("[-] Passwords do not match."); System.exit(1);
        }
        vault.createVault(pw1);
        Arrays.fill(pw1, '\0'); Arrays.fill(pw2, '\0');
    }

    private static boolean unlockVault() throws Exception {
        System.out.println("[*] Vault found. Please authenticate.");
        for (int i = 1; i <= 3; i++) {
            char[] pw = readPassword("    Master password (attempt " + i + "/3): ");
            if (vault.unlock(pw)) {
                Arrays.fill(pw, '\0');
                System.out.println("[+] Access granted.\n");
                return true;
            }
            Arrays.fill(pw, '\0');
            System.out.println("[-] Incorrect password.");
        }
        return false;
    }

    private static void runMenu() throws Exception {
        boolean running = true;
        while (running) {
            printMenu();
            String choice = input.nextLine().trim();
            System.out.println();
            switch (choice) {
                case "1" -> addCredential();
                case "2" -> retrievePassword();
                case "3" -> vault.listCredentials();
                case "4" -> deleteCredential();
                case "0" -> running = false;
                default  -> System.out.println("[!] Invalid option.");
            }
            if (running && !choice.equals("0")) pause();
        }
    }

    private static void addCredential() throws Exception {
        String site = readNonBlank("  Site name : ");
        String user = readNonBlank("  Username  : ");
        char[] pw   = readPasswordNonBlank("  Password  : ");
        vault.addCredential(site, user, new String(pw));
        Arrays.fill(pw, '\0');
    }

    private static void retrievePassword() throws Exception {
        String site = readNonBlank("  Site name : ");
        List<Credential> matches = vault.getCredentialsForSite(site);

        if (matches.isEmpty()) {
            System.out.println("[-] No credential found for: " + site);
            return;
        }

        Credential chosen;
        if (matches.size() == 1) {
            chosen = matches.get(0);
        } else {
            System.out.println("  Multiple accounts found for " + site + ":");
            for (int i = 0; i < matches.size(); i++)
                System.out.printf("  [%d] %s%n", i + 1, matches.get(i).getUsername());
            System.out.print("  Select account: ");
            int pick;
            try {
                pick = Integer.parseInt(input.nextLine().trim()) - 1;
                if (pick < 0 || pick >= matches.size()) throw new NumberFormatException();
            } catch (NumberFormatException e) {
                System.out.println("[!] Invalid selection."); return;
            }
            chosen = matches.get(pick);
        }

        System.out.println("[+] Password : " + vault.decryptPassword(chosen));
        System.out.println("    (clear terminal after use)");
    }

    private static void deleteCredential() throws Exception {
        String site = readNonBlank("  Site name : ");
        List<Credential> matches = vault.getCredentialsForSite(site);

        if (matches.isEmpty()) {
            System.out.println("[-] No credential found for: " + site);
            return;
        }

        String username;
        if (matches.size() == 1) {
            username = matches.get(0).getUsername();
        } else {
            System.out.println("  Multiple accounts found for " + site + ":");
            for (int i = 0; i < matches.size(); i++)
                System.out.printf("  [%d] %s%n", i + 1, matches.get(i).getUsername());
            System.out.print("  Select account to delete: ");
            int pick;
            try {
                pick = Integer.parseInt(input.nextLine().trim()) - 1;
                if (pick < 0 || pick >= matches.size()) throw new NumberFormatException();
            } catch (NumberFormatException e) {
                System.out.println("[!] Invalid selection."); return;
            }
            username = matches.get(pick).getUsername();
        }

        if (vault.deleteCredential(site, username))
            System.out.println("[+] Deleted: " + site + " / " + username);
        else
            System.out.println("[-] Could not delete.");
    }

    private static String readNonBlank(String prompt) {
        while (true) {
            System.out.print(prompt);
            String val = input.nextLine().trim();
            if (!val.isEmpty()) return val;
            System.out.println("[!] Cannot be blank.");
        }
    }

    private static char[] readPasswordNonBlank(String prompt) {
        while (true) {
            char[] pw = readPassword(prompt);
            if (pw.length > 0) return pw;
            System.out.println("[!] Password cannot be blank.");
        }
    }

    private static void printBanner() {
        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║   AES-256 Password Manager v3.0      ║");
        System.out.println("║   PBKDF2 · GCM · Honours Project     ║");
        System.out.println("╚══════════════════════════════════════╝");
        System.out.println();
    }

    private static void printMenu() {
        clearScreen();
        System.out.println("┌─────────────────────────────┐");
        System.out.println("│  1. Add credential          │");
        System.out.println("│  2. Retrieve password       │");
        System.out.println("│  3. List all sites          │");
        System.out.println("│  4. Delete credential       │");
        System.out.println("│  0. Exit & lock vault       │");
        System.out.println("└─────────────────────────────┘");
        System.out.print("Choice: ");
    }

    private static void clearScreen() {
        try {
            if (System.getProperty("os.name").toLowerCase().contains("win"))
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            else { System.out.print("\033[H\033[2J"); System.out.flush(); }
        } catch (Exception ignored) { System.out.println("\n\n\n"); }
    }

    private static void pause() {
        System.out.print("\n  Press Enter to continue...");
        input.nextLine();
    }

    private static char[] readPassword(String prompt) {
        Console c = System.console();
        if (c != null) return c.readPassword(prompt);
        System.out.print(prompt + "[visible] ");
        return input.nextLine().toCharArray();
    }
}