
import math
import string
import re

COMMON_PASSWORDS = {
    "password", "password123", "123456",
    "123456789", "qwerty", "abc123",
    "admin", "letmein", "welcome",
    "iloveyou", "pass123", "admin123"
}

COMMON_WORDS = {
    "password", "admin", "welcome",
    "love", "hello", "user", "login"
}


def analyze_password(password):

    length = len(password)
    issues = []
    score = 100

    lower_password = password.lower()

    # 1. Check common passwords
    if lower_password in COMMON_PASSWORDS:
        return length, 0, 0, "Weak", [
            "This is a commonly used password."
        ]

    # 2. Check password length
    if length < 8:
        score -= 30
        issues.append("Password is too short.")

    elif length < 12:
        score -= 10
        issues.append("Consider using a longer password.")

    # 3. Check character variety
    categories = 0

    if any(c.islower() for c in password):
        categories += 1

    if any(c.isupper() for c in password):
        categories += 1

    if any(c.isdigit() for c in password):
        categories += 1

    if any(c in string.punctuation for c in password):
        categories += 1

    if categories < 3:
        score -= 20
        issues.append("Password has limited character variety.")

    # 4. Check repeated characters
    if re.search(r"(.)\1{2,}", password):
        score -= 20
        issues.append("Contains repeated characters.")

    # 5. Check sequential patterns
    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]

    for sequence in sequences:
        if any(sequence[i:i+4] in lower_password
               for i in range(len(sequence)-3)):
            score -= 20
            issues.append("Contains predictable sequences.")
            break

    # 6. Check common dictionary words
    for word in COMMON_WORDS:
        if word in lower_password:
            score -= 25
            issues.append("Contains a common dictionary word.")
            break

    # 7. Calculate estimated entropy
    pool = 0

    if any(c.islower() for c in password):
        pool += 26

    if any(c.isupper() for c in password):
        pool += 26

    if any(c.isdigit() for c in password):
        pool += 10

    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)

    if pool > 0:
        entropy = length * math.log2(pool)
    else:
        entropy = 0

    # 8. Final score
    score = max(0, min(score, 100))

    if score < 30:
        strength = "Weak"
    elif score < 50:
        strength = "Moderate"
    elif score < 75:
        strength = "Strong"
    else:
        strength = "Very Strong"

    if not issues:
        issues.append("No basic predictable patterns detected.")

    return length, entropy, score, strength, issues


# Main program

print("=" * 45)
print("       PASSWORD STRENGTH ANALYZER")
print("=" * 45)

password = input("Enter your password: ")

length, entropy, score, strength, issues = analyze_password(password)

print("\n========== ANALYSIS RESULT ==========")

print("Password Length :", length, "characters")
print("Estimated Entropy:", round(entropy, 2), "bits")
print("Password Score  :", score, "/ 100")
print("Password Strength:", strength)

print("\n========== SECURITY FEEDBACK ==========")

for issue in issues:
    print("-", issue)

print("=" * 45)
