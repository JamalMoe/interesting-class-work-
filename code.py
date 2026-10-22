import os
import json
import re
import hashlib
import secrets
from datetime import datetime

# Create the results folder if it does not exist.
os.makedirs("results", exist_ok=True)


# Hash a password using PBKDF2 and a random salt.
def hash_password(password):
    salt = secrets.token_bytes(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )

    # Store the salt and hash together as hexadecimal strings.
    return {
        "salt": salt.hex(),
        "hash": hashed.hex()
    }


# Check whether a password matches a stored hash.
def verify_password(password, stored):
    salt = bytes.fromhex(stored["salt"])

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )

    # compare_digest avoids ordinary string comparison for secrets.
    return secrets.compare_digest(
        hashed.hex(),
        stored["hash"]
    )


# Evaluate password strength.
def check_password(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 20
    else:
        feedback.append("Use at least 8 characters.")

    if len(password) >= 12:
        score += 10

    if re.search(r"[A-Z]", password):
        score += 15
    else:
        feedback.append("Add an uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 15
    else:
        feedback.append("Add a lowercase letter.")

    if re.search(r"\d", password):
        score += 15
    else:
        feedback.append("Add a number.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 15
    else:
        feedback.append("Add a special character.")

    # Penalize very common or predictable passwords.
    common = ["password", "12345678", "qwerty123", "admin123"]

    if password.lower() in common:
        score = min(score, 20)
        feedback.append("Avoid common passwords.")

    return min(score, 100), feedback


# Assign a grade based on a score out of 100.
def get_grade(score):
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "E"


# Collect and validate the registration details.
def register_user():
    print("\n=== STUDENT REGISTRATION ===")

    name = input("Full name: ").strip()

    while not name:
        print("Name cannot be empty.")
        name = input("Full name: ").strip()

    while True:
        email = input("Email address: ").strip()

        # A simple format check for a classroom example.
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            break

        print("Please enter a valid email address.")

    while True:
        age_text = input("Age: ").strip()

        try:
            age = int(age_text)

            if 13 <= age <= 120:
                break

            print("Age must be between 13 and 120.")

        except ValueError:
            print("Enter a whole number.")

    while True:
        password = input("Create a password: ")

        score, feedback = check_password(password)

        print(f"\nPassword strength score: {score}/100")
        print(f"Password grade: {get_grade(score)}")

        if feedback:
            print("Suggestions:")
            for suggestion in feedback:
                print(f"- {suggestion}")

        if score >= 60:
            confirmation = input(
                "Confirm password: "
            )

            if secrets.compare_digest(password, confirmation):
                break

            print("Passwords do not match. Try again.")

        else:
            print("Password score is too low. Try again.")

    # Never save the original password in the results file.
    password_data = hash_password(password)

    # Verify that the hash works before saving the registration.
    hash_verified = verify_password(password, password_data)

    # Score the registration details.
    registration_score = 0
    checks = {
        "Name provided": bool(name),
        "Email format valid": bool(
            re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
        ),
        "Age in accepted range": 13 <= age <= 120,
        "Password sufficiently strong": score >= 60,
        "Password confirmation matched": True,
        "Password hash verified": hash_verified
    }

    for passed in checks.values():
        if passed:
            registration_score += 100 / len(checks)

    registration_score = round(registration_score)
    grade = get_grade(registration_score)

    # Build the registration record.
    record = {
        "registered_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "name": name,
        "email": email,
        "age": age,
        "password_hash": password_data,
        "password_strength_score": score,
        "password_grade": get_grade(score),
        "registration_checks": checks,
        "registration_score": registration_score,
        "registration_grade": grade
    }

    # Use a timestamp and random suffix to create a unique filename.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = (
        f"results/registration_{timestamp}_"
        f"{secrets.token_hex(4)}.json"
    )

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(record, file, indent=4)

    print("\n=== REGISTRATION RESULTS ===")
    print(f"Name: {name}")
    print(f"Email: {email}")
    print(f"Password strength: {score}/100")
    print(f"Registration score: {registration_score}/100")
    print(f"Registration grade: {grade}")
    print(f"Password hash verified: {hash_verified}")
    print(f"Results saved to: {filename}")


# Main menu: users can register multiple times or exit.
def main():
    while True:
        print("\n=== REGISTRATION SYSTEM ===")
        print("1. Register")
        print("2. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            try:
                register_user()
            except (OSError, ValueError) as error:
                print(f"Could not complete registration: {error}")

        elif choice == "2":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Select 1 or 2.")


if __name__ == "__main__":
    main()
