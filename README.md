# password-manager
import json
import hashlib
import string
from datetime import datetime
import secrets
import tkinter as tk
from tkinter import messagebox, Toplevel, Label, Entry, Button, BooleanVar, Checkbutton


# Function to generate a password based on user options.
def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_special=True):
    characters = ''
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation

    if not characters:
        return "Error: No character types selected!"

    password = ''.join(secrets.choice(characters) for _ in range(length))
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    return ''.join(password_list)


# Function to check the strength of a password.
def check_password_strength(password):
    if len(password) < 12:
        return "Weak: Password should be at least 12 characters long."
    elif not any(char.isdigit() for char in password):
        return "Weak: Password should contain at least one digit."
    elif not any(char.isalpha() for char in password):
        return "Weak: Password should contain at least one letter."
    elif not any(char.isupper() for char in password):
        return "Weak: Password should contain at least one uppercase letter."
    elif not any(char in string.punctuation for char in password):
        return "Weak: Password should contain at least one special character."
    else:
        return "Strong: Password meets OWASP guidelines."


# Function to create a new account.
def create_account_window():
    account_window = Toplevel(root)
    account_window.title("Create Account")

    Label(account_window, text="Enter your desired username:").pack(pady=5)
    username_entry = Entry(account_window)
    username_entry.pack(pady=5)

    Label(account_window, text="Enter your desired password:").pack(pady=5)
    password_entry = Entry(account_window, show="*")
    password_entry.pack(pady=5)

    def save_account():
        username = username_entry.get()
        password = password_entry.get()
        if username and password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            passwords[username] = {
                'hashed_password': hashed_password,
                'last_password_change': datetime.now().isoformat()
            }
            previous_passwords[username] = [password]
            save_to_file(passwords)
            save_previous_passwords()
            messagebox.showinfo("Success", "Account created successfully!")
            account_window.destroy()

    Button(account_window, text="Create Account", command=save_account).pack(pady=10)


# Function to add a password to the manager.
def add_password_window():
    add_window = Toplevel(root)
    add_window.title("Add Password")

    Label(add_window, text="Enter the website or app name:").pack(pady=5)
    website_entry = Entry(add_window)
    website_entry.pack(pady=5)

    Label(add_window, text="Enter your username:").pack(pady=5)
    username_entry = Entry(add_window)
    username_entry.pack(pady=5)

    Label(add_window, text="Enter your password:").pack(pady=5)
    password_entry = Entry(add_window, show="*")
    password_entry.pack(pady=5)

    def save_password():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        if website and username and password:
            password_policy_result = check_password_policy(password, previous_passwords.get(username, []), datetime.now())
            if "Strong" in password_policy_result:
                passwords[website] = {'username': username, 'password': password}
                if username not in previous_passwords:
                    previous_passwords[username] = []
                previous_passwords[username].append(password)
                save_to_file(passwords)
                save_previous_passwords()
                messagebox.showinfo("Success", "Password added successfully!")
                add_window.destroy()
            else:
                messagebox.showwarning("Password Policy", password_policy_result)

    Button(add_window, text="Add Password", command=save_password).pack(pady=10)


# Function to retrieve a saved password.
def retrieve_password_window():
    retrieve_window = Toplevel(root)
    retrieve_window.title("Retrieve Password")

    Label(retrieve_window, text="Enter the website or app name:").pack(pady=5)
    website_entry = Entry(retrieve_window)
    website_entry.pack(pady=5)

    def retrieve_password():
        website = website_entry.get()
        if website in passwords:
            messagebox.showinfo("Password Retrieved",
                                f"Username: {passwords[website]['username']}\nPassword: {passwords[website]['password']}")
            retrieve_window.destroy()
        else:
            messagebox.showwarning("Error", "Password not found for the specified website.")

    Button(retrieve_window, text="Retrieve Password", command=retrieve_password).pack(pady=10)


# Function to generate a password with character selection.
def generate_password_window():
    generate_window = Toplevel(root)
    generate_window.title("Generate Password")

    Label(generate_window, text="Enter password length (default is 16):").pack(pady=5)
    length_entry = Entry(generate_window)
    length_entry.insert(0, "16")
    length_entry.pack(pady=5)

    use_upper = BooleanVar(value=True)
    use_lower = BooleanVar(value=True)
    use_digits = BooleanVar(value=True)
    use_special = BooleanVar(value=True)

    Checkbutton(generate_window, text="Include Uppercase Letters", variable=use_upper).pack()
    Checkbutton(generate_window, text="Include Lowercase Letters", variable=use_lower).pack()
    Checkbutton(generate_window, text="Include Digits", variable=use_digits).pack()
    Checkbutton(generate_window, text="Include Special Characters", variable=use_special).pack()

    def generate_and_display_password():
        length = int(length_entry.get())
        generated_password = generate_password(length, use_upper.get(), use_lower.get(), use_digits.get(), use_special.get())
        strength_result = check_password_strength(generated_password)

        if "Strong" in strength_result:
            messagebox.showinfo("Generated Password",
                                f"Your generated password is: {generated_password}\nPassword Strength: {strength_result}")
        else:
            messagebox.showwarning("Password Strength",
                                   f"Generated password is weak: {strength_result}\nPlease try again with different options.")
        generate_window.destroy()

    Button(generate_window, text="Generate", command=generate_and_display_password).pack(pady=10)


# Function to check the strength of a password.
def check_password_strength_window():
    strength_window = Toplevel(root)
    strength_window.title("Check Password Strength")

    Label(strength_window, text="Enter the password to check its strength:").pack(pady=5)
    password_entry = Entry(strength_window, show="*")
    password_entry.pack(pady=5)

    def check_strength():
        password = password_entry.get()
        if password:
            strength_result = check_password_strength(password)
            messagebox.showinfo("Password Strength", strength_result)
            strength_window.destroy()

    Button(strength_window, text="Check Strength", command=check_strength).pack(pady=10)


# Function to save passwords to a file.
def save_to_file(data):
    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)


# Function to load passwords from a file.
def load_from_file():
    try:
        with open('passwords.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


# Function to save previous passwords to a file.
def save_previous_passwords():
    with open('previous_passwords.json', 'w') as file:
        json.dump(previous_passwords, file, indent=4)


# Function to load previous passwords from a file.
def load_previous_passwords():
    try:
        with open('previous_passwords.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


# Main function to create the password manager.
def create_password_manager():
    global passwords, previous_passwords, root
    passwords = load_from_file()
    previous_passwords = load_previous_passwords()

    root = tk.Tk()
    root.title("Password Manager")

    Button(root, text="Create Account", command=create_account_window).pack(pady=5)
    Button(root, text="Add Password", command=add_password_window).pack(pady=5)
    Button(root, text="Retrieve Password", command=retrieve_password_window).pack(pady=5)
    Button(root, text="Generate Password", command=generate_password_window).pack(pady=5)
    Button(root, text="Check Password Strength", command=check_password_strength_window).pack(pady=5)
    Button(root, text="Exit", command=root.quit).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_password_manager()
