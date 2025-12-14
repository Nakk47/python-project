import hashlib
import json
import os
import base64
import random
from random import choice as pick_one
from random import shuffle
from string import ascii_letters, digits, punctuation
from typing import Dict
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- MasterKeyManager Class ---

class MasterKeyManager:
    MASTER_KEY_FILE = "master_key.hash"
    SALT_FILE = "salt.bin"
    
    def __init__(self):
        self._master_hash = self._get_master_hash() # Changed to _get_master_hash for proper loading
        self._secret_salt_data = self._get_salt_file() # Changed to _get_salt_file for proper loading
        self._derived_fernet_key = None 

    # Helper methods for file operations (already correct)
    def _make_salt_data(self):
        return os.urandom(16)
    def _get_salt_file(self):
        try:
            with open(self.SALT_FILE, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None
    def _save_salt_file(self, salt_data: bytes):
        with open(self.SALT_FILE, "wb") as f:
            f.write(salt_data)
    def _get_master_hash(self):
        try:
            with open(self.MASTER_KEY_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
        except FileNotFoundError:
            return None
    def _save_master_hash(self, the_hash: str):
        with open(self.MASTER_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(the_hash)
    def _make_quick_hash(self, user_password: str):
        return hashlib.sha256(user_password.encode()).hexdigest()
    
    # Core logic (already correct)
    def is_setup(self):
        return self._master_hash is not None and self._secret_salt_data is not None
    def setup_master_password(self, new_password: str):
        if self.is_setup() or not new_password:
            return False
        self._master_hash = self._make_quick_hash(new_password)
        self._save_master_hash(self._master_hash)
        self._secret_salt_data = self._make_salt_data()
        self._save_salt_file(self._secret_salt_data)
        return True
    def verify_and_get_key(self, password_input: str):
        if not self.is_setup():
            return False
        if self._make_quick_hash(password_input) != self._master_hash:
            return False
        # PBKDF2HMAC for strong key derivation (key stretching)
        kdf_tool = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._secret_salt_data,
            iterations=480000, 
        )
        key_bytes = kdf_tool.derive(password_input.encode())
        self._derived_fernet_key = base64.urlsafe_b64encode(key_bytes)
        return True

# --- VaultManager Class ---

class VaultManager(MasterKeyManager):
    VAULT_FILE = "secure_vault.dat"

    def __init__(self):
        super().__init__()
        self._customer_data: Dict[str, Dict[str, str]] = {}
        self._authenticated = False
        self._cipher_engine = None 

    def _encrypt_data(self, plaintext: str):
        if not self._cipher_engine:
            raise Exception("Can't encrypt: Encryption is off!")
        return self._cipher_engine.encrypt(plaintext.encode())

    # 🟢 ADDED: Decryption Method
    def _decrypt_data(self, locked_data: bytes):
        if not self._cipher_engine:
            raise Exception("Can't decrypt: Encryption is off!")
        try:
            return self._cipher_engine.decrypt(locked_data).decode()
        except InvalidToken:
            # Handle incorrect password or corrupted file during decryption
            print("Decryption failed: Incorrect master password or corrupted vault data.")
            return None

    def _load_vault_data(self):
        if not self._cipher_engine:
            return
        try:
            with open(self.VAULT_FILE, "rb") as f:
                locked_data = f.read()

                if not locked_data:
                    self._customer_data = {}
                    return

                unlocked_string = self._decrypt_data(locked_data)

                if unlocked_string:
                    try:
                        self._customer_data = json.loads(unlocked_string)
                    except json.JSONDecodeError:
                        self._customer_data = {} 
                else:
                    self._customer_data = {}
        except FileNotFoundError:
            self._customer_data = {} 
        except Exception:
            self._customer_data = {} 

    def _save_vault_data(self):
        if not self._cipher_engine:
            return

        try:
            json_text = json.dumps(self._customer_data)
            locked_bytes = self._encrypt_data(json_text)

            with open(self.VAULT_FILE, "wb") as f:
                f.write(locked_bytes)

            print("Vault saved successfully to the hard drive.")
        except Exception as e:
            print(f"Error saving vault data: {e}")

    def manager_login(self):
        # ... (rest of manager_login is correct)
        if self._authenticated:
            print("Vault is already open.")
            return True

        if not self.is_setup():
            print("\n--- First-Time Manager Setup ---")
            new_pass = input("Set your brand NEW Master Password: ")

            if not new_pass:
                print("Password cannot be empty. Setup canceled.")
                return False

            if not self.setup_master_password(new_pass):
                print("Failed to finish the master password setup.")
                return False

            if self.verify_and_get_key(new_pass):
                self._cipher_engine = Fernet(self._derived_fernet_key)
                self._authenticated = True
                self._customer_data = {}
                print("Setup complete! Vault is ready to use.")
                return True
            return False

        print("\n--- Manager Login ---")
        password_attempt = input("Enter Master Password: ")

        if self.verify_and_get_key(password_attempt):
            self._cipher_engine = Fernet(self._derived_fernet_key)
            self._authenticated = True
            self._load_vault_data()
            print("Manager login successful! Welcome back.")
            return True
        else:
            print("Incorrect Master Password. Access denied.")
            return False

    def lock_vault(self):
        # ... (lock_vault is correct)
        if not self._authenticated:
            print("Vault is already locked, nothing to do.")
            return

        self._customer_data = {}
        self._cipher_engine = None 
        self._authenticated = False
        print("Vault is now LOCKED. Memory is cleared.")

    def register_customer(self, name: str, password: str, email: str = "N/A"):
        # ... (register_customer is correct)
        if not self._authenticated:
            print("Vault locked. Manager needs to log in first.")
            return False
            
        if not name or name in self._customer_data:
            print(f"Bad name or account '{name}' already exists.")
            return False

        self._customer_data[name] = {"email": email, "password": password}
        self._save_vault_data()
        print(f"Account '{name}' has been created.")
        return True

    def update_password(self, account_name: str, new_password: str):
        # ... (update_password is correct)
        if not self._authenticated or account_name not in self._customer_data:
            return False
            
        self._customer_data[account_name]["password"] = new_password
        self._save_vault_data()
        print(f"Password for '{account_name}' has been changed.")
        return True

    def view_accounts_summary(self):
        # ... (view_accounts_summary is correct)
        if not self._authenticated or not self._customer_data:
            print("Vault locked or no accounts saved yet.")
            return

        print("\n--- List of Saved Accounts ---")
        for name, data in self._customer_data.items():
            print(f"Account ID: {name}")
            print(f"  Email: {data.get('email','N/A')}")
            print("  Password: (Hidden)")
        print("-------------------------------\n")

    def customer_login(self, account_name: str, password_attempt: str):
        # ... (customer_login is correct)
        if not self._authenticated:
            print("The system is locked. The manager must open it first.")
            return False
            
        if account_name not in self._customer_data:
            print("Account not found.")
            return False

        if self._customer_data[account_name].get("password") == password_attempt:
            print(f"Login successful! Hello, {account_name}!")
            return True
            
        print("Login failed: Wrong password.")
        return False

    def generate_password(self, length: int = 12):
        # ... (generate_password is correct)
        if length < 8:
            length = 8
            
        all_chars = ascii_letters + digits + punctuation
        pw_chars = [
            pick_one(ascii_letters),
            pick_one(digits),
            pick_one(punctuation),
        ]
        pw_chars += [pick_one(all_chars) for _ in range(length - len(pw_chars))]
        shuffle(pw_chars)
        return "".join(pw_chars)
        
    # 🟢 ADDED: Manager lookup method
    def get_customer_password(self, account_name: str):
        """Allows manager to retrieve a stored password if authenticated."""
        if not self._authenticated:
            print("Vault locked.")
            return None
        
        account_data = self._customer_data.get(account_name)
        if not account_data:
            print(f"Account '{account_name}' not found.")
            return None
            
        return account_data.get("password")

    # 🟢 ADDED: Email lookup method
    def find_account_by_email(self, email_input: str):
        """Finds account name by looking up email address."""
        if not self._authenticated:
            return None
        
        email_input = email_input.lower()
        for name, data in self._customer_data.items():
            if data.get("email", "").lower() == email_input:
                return name
        return None


# --- Menu and Run Functions (Corrected/Completed) ---

def manager_menu():
    print("\n--- Manager Menu ---")
    print("1. See All Saved Accounts (Names/Emails)")
    print("2. Look Up a Specific Password (USE CAREFULLY!)")
    print("3. Get a Strong New Password")
    print("4. Go Back to Main Menu (Keep Vault Open)")
    return input("Manager's Choice (1-4): ")

def customer_menu(account: str):
    print(f"\n--- Your Account Menu: {account} ---")
    print("1. View Your Password")
    print("2. Change Your Password")
    print("3. Log Out")
    return input("Customer Choice (1-3): ")

def main_menu(is_unlocked: bool):
    print("\n--- Welcome to SecurePassVault ---")
    print("1. Manager Access")
    print("2. Customer Access (Log In/Sign Up/Forgot)")
    if is_unlocked:
        print("3. LOCK VAULT (Clears memory and protects data)")
        print("4. Close Program")
        return input("Choose an Option (1-4): ")
    else:
        print("3. Close Program")
        return input("Choose an Option (1-3): ")

def run_manager_mode(vault: VaultManager):
    if not vault.manager_login():
        return

    while True:
        choice = manager_menu()
        if choice == "1":
            vault.view_accounts_summary()
        elif choice == "2":
            name = input("Enter the account name you need the password for: ")
            pw = vault.get_customer_password(name) # Now correctly implemented
            if pw:
                print(f"Password for {name} is: {pw}")
                print("REMEMBER: This is plain text! Be careful!")
        elif choice == "3":
            try:
                length_str = input("How long should the password be? (Default is 12): ")
                length = int(length_str) if length_str else 12
            except ValueError:
                length = 12
            print("Your generated password:", vault.generate_password(length))
        elif choice == "4":
            print("Exiting Manager Menu. The vault stays open.")
            break
        else:
            print("Invalid choice. Try again.")


def run_customer_mode(vault: VaultManager):
    if not vault.is_setup() or not vault._authenticated:
        print("The system isn't ready or is locked. The manager must start first.")
        return

    print("\n--- Customer Access ---")
    print("1. Log In / Sign Up")
    print("2. Forgot Password")
    access_choice = input("Select an option (1 or 2): ")


    if access_choice == "2":
        # --- Forgot Password Flow ---
        print("\n--- Forgot Password Request ---")
        print("To reset your password, you must contact a Manager.")
        account_name = input("Enter your Account Name/ID: ")

        if account_name not in vault._customer_data:
            print("Account not found. Cannot proceed with reset.")
            return

        # Manager can look up and display the email to verify identity
        stored_email = vault._customer_data[account_name].get("email", "N/A")
        print(f"Account Email on file: {stored_email}")
        
        # This acts as the high-privilege authorization for password reset
        manager_confirm = input("Are you the Manager authorizing this reset? (yes/no): ").lower()
        if manager_confirm != 'yes':
            print("Password reset cancelled.")
            return

        new_password = vault.generate_password()
        
        if vault.update_password(account_name, new_password):
            print("\n**!!! PASSWORD RESET SUCCESSFUL !!!**")
            print(f"Account: {account_name}")
            print(f"Temporary New Password: {new_password}")
            print("The user should log in immediately and change this temporary password.")
        else:
            print("Password reset failed.")
        return

    elif access_choice != "1":
        print("Invalid choice. Going back to main menu.")
        return

    # --- Log In / Sign Up Flow (Option 1) ---

    account_name_input = input("Enter your Account Name/ID: ")


    if account_name_input in vault._customer_data:
        account_name = account_name_input
    else:
        # Find account by email (now correctly implemented)
        found = vault.find_account_by_email(account_name_input) 
        account_name = found if found else account_name_input

    password = ""
    logged_in_account = None

    if account_name not in vault._customer_data:
        # Sign Up Flow
        print(f"Account '{account_name}' isn't here.")
        reg = input("Want to sign up for a new account? (y/n): ").lower()

        if reg == "y":
            gen = input("Do you want the system to generate a strong password for you? (y/n): ").lower()

            if gen == "y":
                password = vault.generate_password()
                print("Generated Password:", password)
            else:
                password = input("Enter your Password: ")
                confirm = input("Confirm Password: ")

                if not password or password != confirm:
                    print("Passwords didn't match or were empty. Sign up failed.")
                    return
            recovery_email = input("Enter your Email Address for password reset (recommended): ")
            if vault.register_customer(account_name, password, email=recovery_email):
                print("Sign up successful! Logging you in...")
                logged_in_account = account_name
            else:
                return
        else:
            print("Access denied.")
            return
    else:
        # Log In Flow
        password_attempt = input(f"Enter password for account '{account_name}': ")
        if vault.customer_login(account_name, password_attempt):
            logged_in_account = account_name
        else:
            return

    # Post-Login menu for customer
    if logged_in_account:
        while True:
            cust_choice = customer_menu(logged_in_account)

            if cust_choice == "1":
                # Assuming customer wants to see their password *after* successful login
                pw = vault.get_customer_password(logged_in_account)
                print(f"\nYour current password: {pw}")
            elif cust_choice == "2":
                new_password = input("Enter your NEW password: ")
                confirm = input("Confirm NEW password: ")
                if new_password and new_password == confirm:
                    if vault.update_password(logged_in_account, new_password):
                        print("Password updated successfully.")
                    else:
                        print("Failed to update password.")
                else:
                    print("Passwords did not match or were empty. Update cancelled.")
            elif cust_choice == "3":
                print(f"Logging out of account: {logged_in_account}.")
                break
            else:
                print("Invalid choice.")

# 🟢 CORRECTED: Main execution block
if __name__ == "__main__":
    vault = VaultManager() # Initialize the vault once
    
    while True:
        is_unlocked = vault._authenticated
        choice = main_menu(is_unlocked)

        if choice == "1":
            run_manager_mode(vault)
        elif choice == "2":
            run_customer_mode(vault)
        elif choice == "3":
            if is_unlocked:
                vault.lock_vault()
            else:
                print("Closing SecurePassVault. Bye!")
                break
        elif choice == "4" and is_unlocked:
            print("Closing SecurePassVault. Bye!")
            break
        else:
            print("Invalid selection.")