using System.Security.Cryptography;
using System.Text;

const string CharacterPool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
const string UpperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const string LowerChars = "abcdefghijklmnopqrstuvwxyz";
const string DigitChars = "0123456789";
const string SymbolChars = "!@#$%^&*()-_=+";

while (true)
{
    Console.Clear();
    Console.WriteLine("=== PASSWORD SECURITY AUDITOR & GENERATOR ===");
    Console.WriteLine("[1] Audit a password");
    Console.WriteLine("[2] Generate a strong password");
    Console.WriteLine("[3] Exit");
    Console.Write("\nChoose an option (1-3): ");

    string choice = Console.ReadLine()?.Trim() ?? "";

    if (choice == "3")
    {
        break;
    }

    if (choice == "2")
    {
        Console.Write("Desired password length (e.g., 16): ");
        string lengthInput = Console.ReadLine() ?? "";

        if (!int.TryParse(lengthInput, out int length) || length < 4 || length > 128)
        {
            Console.WriteLine("\n[!] Enter a valid number between 4 and 128.");
            Console.WriteLine("Press any key to return to the menu...");
            Console.ReadKey();
            continue;
        }

        string generated = GenerateStrongPassword(length, CharacterPool);
        Console.WriteLine($"\nGenerated Password ({length} chars): {generated}");
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
        continue;
    }

    if (choice != "1")
    {
        Console.WriteLine("\n[!] Invalid option.");
        Console.WriteLine("Press any key to try again...");
        Console.ReadKey();
        continue;
    }

    Console.Write("\nEnter a password to audit: ");
    string password = Console.ReadLine() ?? "";

    var initialAudit = EvaluatePassword(password);
    PrintAuditReport(password, initialAudit);

    if (initialAudit.Score < 75)
    {
        Console.WriteLine("\nScore is below 75/100. Adding characters to reach 100/100...");
        string upgradedPassword = StrengthenToMaxScore(password);
        var upgradedAudit = EvaluatePassword(upgradedPassword);

        Console.WriteLine($"\nUpgraded Password ({upgradedPassword.Length} chars): {upgradedPassword}");
        PrintAuditReport(upgradedPassword, upgradedAudit);
    }

    Console.WriteLine("\nPress any key to return to the menu...");
    Console.ReadKey();
}

static (int Score, bool HasUpper, bool HasLower, bool HasDigit, bool HasSymbol, bool HasWeakPattern) EvaluatePassword(string password)
{
    bool hasUpper = false;
    bool hasLower = false;
    bool hasDigit = false;
    bool hasSymbol = false;

    foreach (char character in password)
    {
        if (char.IsUpper(character)) hasUpper = true;
        else if (char.IsLower(character)) hasLower = true;
        else if (char.IsDigit(character)) hasDigit = true;
        else hasSymbol = true;
    }

    int score = 0;
    if (password.Length >= 8) score += 20;
    if (password.Length >= 12) score += 20;
    if (hasUpper) score += 15;
    if (hasLower) score += 15;
    if (hasDigit) score += 15;
    if (hasSymbol) score += 15;

    string lowerPassword = password.ToLower();
    bool hasWeakPattern = lowerPassword.Contains("password") || lowerPassword.Contains("1234") || lowerPassword.Contains("admin");

    if (hasWeakPattern)
    {
        score -= 30;
        if (score < 0) score = 0;
    }

    return (score, hasUpper, hasLower, hasDigit, hasSymbol, hasWeakPattern);
}

static string StrengthenToMaxScore(string original)
{
    StringBuilder sb = new StringBuilder(original);
    int safetyCounter = 0;

    while (safetyCounter < 200)
    {
        string current = sb.ToString();
        var audit = EvaluatePassword(current);

        if (audit.Score >= 100)
        {
            break;
        }

        // Prioritize missing categories first, then add length/variety using cryptographic randomness
        char nextChar;
        if (!audit.HasUpper)
            nextChar = UpperChars[RandomNumberGenerator.GetInt32(UpperChars.Length)];
        else if (!audit.HasLower)
            nextChar = LowerChars[RandomNumberGenerator.GetInt32(LowerChars.Length)];
        else if (!audit.HasDigit)
            nextChar = DigitChars[RandomNumberGenerator.GetInt32(DigitChars.Length)];
        else if (!audit.HasSymbol)
            nextChar = SymbolChars[RandomNumberGenerator.GetInt32(SymbolChars.Length)];
        else
            nextChar = CharacterPool[RandomNumberGenerator.GetInt32(CharacterPool.Length)];

        sb.Append(nextChar);
        safetyCounter++;
    }

    return sb.ToString();
}

static void PrintAuditReport(string password, (int Score, bool HasUpper, bool HasLower, bool HasDigit, bool HasSymbol, bool HasWeakPattern) audit)
{
    if (audit.HasWeakPattern)
    {
        Console.WriteLine("\n[!] WARNING: Predictable dictionary/sequence pattern detected (-30 pts).");
    }

    Console.WriteLine("\n--- Audit Breakdown ---");
    Console.WriteLine($"Length ({password.Length} chars): {(password.Length >= 12 ? "Strong" : password.Length >= 8 ? "Okay" : "Too Short")}");
    Console.WriteLine($"Uppercase Letters:  {(audit.HasUpper ? "Yes" : "Missing")}");
    Console.WriteLine($"Lowercase Letters:  {(audit.HasLower ? "Yes" : "Missing")}");
    Console.WriteLine($"Numbers:            {(audit.HasDigit ? "Yes" : "Missing")}");
    Console.WriteLine($"Special Symbols:    {(audit.HasSymbol ? "Yes" : "Missing")}");
    Console.WriteLine($"Security Score:     {audit.Score}/100");

    if (audit.Score >= 85)
        Console.WriteLine("Verdict: STRONG — Resistant to basic brute-force attacks.");
    else if (audit.Score >= 50)
        Console.WriteLine("Verdict: MODERATE — Add more length or symbols.");
    else
        Console.WriteLine("Verdict: WEAK — Easily cracked.");
}

static string GenerateStrongPassword(int length, string pool)
{
    StringBuilder builder = new StringBuilder(length);

    for (int i = 0; i < length; i++)
    {
        int index = RandomNumberGenerator.GetInt32(pool.Length);
        builder.Append(pool[index]);
    }

    return builder.ToString();
}