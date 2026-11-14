 import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * ExistingPolicyChecker  (Member 1's part)
 *
 * PURPOSE:
 *   Checks a password against the organization's EXISTING password policy,
 *   so the team can later compare it with the improved policy (rubric item:
 *   "comparing password rule compliance").
 *
 * WHICH RULES CAN A PROGRAM CHECK?
 *   (a) at least 8 characters ............................ YES  (checked here)
 *   (b) uppercase + lowercase + at least one number ....... YES  (checked here)
 *   (c) change every 60 days .............................. NO   (needs dates/time, not a password check)
 *   (d) cannot reuse previous five passwords .............. YES  (checked here, using a history list)
 *   (e) lock account after 5 failed attempts for 30 min ... NO   (needs login attempts, not a password check)
 *   (f), (g), (h) ......................................... NO   (human behaviour / system settings)
 *
 * HOW OTHER MEMBERS USE THIS CLASS:
 *   List<String> problems = ExistingPolicyChecker.check(password, history);
 *   If the list is EMPTY, the password is compliant with the existing policy.
 *
 * NOTE: This is a teaching demo. A real system must NEVER store passwords in
 * plain text (it stores salted hashes). We keep plain text here only to keep
 * the code simple.
 */
public class ExistingPolicyChecker {

    // "final" means the value can never change. "static" means it belongs to the class itself.
    // Rule (a): minimum length from the policy.
    private static final int MIN_LENGTH = 8;

    // Rule (d): the policy remembers only the LAST five passwords.
    private static final int HISTORY_SIZE = 5;

    /**
     * Checks one password against rules (a), (b) and (d).
     *
     * @param password          the password we want to test
     * @param previousPasswords the user's old passwords, ordered OLDEST first, NEWEST last
     *                          (pass an empty list if there is no history)
     * @return a list of broken rules; an EMPTY list means the password is compliant
     */
    public static List<String> check(String password, List<String> previousPasswords) {

        // This list collects a message for every rule the password breaks.
        List<String> violations = new ArrayList<>();

        // Safety check: if the password is missing, stop immediately.
        // (Without this, password.length() below would crash with a NullPointerException.)
        if (password == null) {
            violations.add("Password is missing.");
            return violations;
        }

        // ---------- Rule (a): at least 8 characters ----------
        if (password.length() < MIN_LENGTH) {
            violations.add("Rule (a): must contain at least " + MIN_LENGTH + " characters.");
        }

        // ---------- Rule (b): uppercase + lowercase + at least one number ----------
        // Three flags, all start as false. We flip each to true when we see a matching character.
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;

        // Look at the password one character at a time (index 0 up to length-1).
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);

            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            }
            // Any other character (like ! or @) is allowed but not required by the existing policy.
        }

        if (!hasUpper) {
            violations.add("Rule (b): must include an uppercase letter.");
        }
        if (!hasLower) {
            violations.add("Rule (b): must include a lowercase letter.");
        }
        if (!hasDigit) {
            violations.add("Rule (b): must include at least one number.");
        }

        // ---------- Rule (d): cannot reuse the previous five passwords ----------
        if (previousPasswords != null) {
            // The newest passwords are at the END of the list, so we only look at the last 5.
            // Math.max(0, ...) protects us when the history has fewer than 5 entries.
            int startIndex = Math.max(0, previousPasswords.size() - HISTORY_SIZE);

            for (int i = startIndex; i < previousPasswords.size(); i++) {
                // equals() compares the TEXT of two Strings (never use == for Strings in Java).
                if (password.equals(previousPasswords.get(i))) {
                    violations.add("Rule (d): password was used within the last " + HISTORY_SIZE + " passwords.");
                    break; // one message is enough, so stop searching
                }
            }
        }

        return violations;
    }

    // =====================================================================
    // Everything below is ONLY a test area so you can run this file alone.
    // When the team builds the shared Main class, this main() can stay or be deleted.
    // =====================================================================

    /** Runs one test and prints a readable result. */
    private static void runTest(String password, List<String> history) {
        List<String> problems = check(password, history);

        System.out.println("Password: " + password);
        if (problems.isEmpty()) {
            System.out.println("  Result: COMPLIANT (accepted by the existing policy)");
        } else {
            System.out.println("  Result: REJECTED");
            for (String p : problems) {
                System.out.println("    - " + p);
            }
        }
        System.out.println();
    }

    // main() is the starting point: when you press Run, Java begins here.
    public static void main(String[] args) {

        // An empty history (the user has no old passwords yet).
        List<String> noHistory = new ArrayList<>();

        System.out.println("=== Existing policy: rule (a) and (b) tests ===\n");
        runTest("abc", noHistory);         // too short, no uppercase, no number -> rejected
        runTest("password", noHistory);    // 8 chars but no uppercase and no number -> rejected
        runTest("Password1", noHistory);   // ACCEPTED, yet extremely common (weakness!)
        runTest("Welcome1", noHistory);    // ACCEPTED, yet very common
        runTest("Summer2026", noHistory);  // ACCEPTED, yet a predictable pattern
        runTest("Ahmed2005", noHistory);   // ACCEPTED, yet built from a name + birth year

        System.out.println("=== Existing policy: rule (d) reuse tests ===\n");

        // History ordered oldest -> newest (3 passwords).
        List<String> shortHistory = Arrays.asList("Winter2025", "Spring2026", "Autumn2025");
        runTest("Spring2026", shortHistory); // reused inside the last 5 -> rejected

        // History with SIX passwords: the oldest one ("Spring2026") is no longer remembered.
        List<String> longHistory = Arrays.asList(
                "Spring2026", "Summer2026", "Autumn2026", "Winter2026", "Spring2027", "Summer2027");
        runTest("Spring2026", longHistory);  // ACCEPTED again after only 6 changes (weakness!)
    }
}



