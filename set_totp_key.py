# set_totp_key.py
import sys
import os

# Add the project directory to the Python path
project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

try:
    from bluep.secure_config import SecureConfig

    # The correct secret key from memory
    correct_secret = "V4SE5CYVQNEU6CQ2V2MAABGR6NDGQTV4"

    print("Attempting to save the correct TOTP secret...")
    config = SecureConfig()
    config.save_secret(correct_secret)
    print(f"Successfully saved secret to: {config.config_path}")

    # Optional: Verify by loading it back (will print the secret)
    print("Verifying saved secret...")
    loaded_secret = config.load_secret()
    if loaded_secret == correct_secret:
        print("Verification successful. Loaded secret matches.")
    else:
        print(f"Verification FAILED. Loaded secret: {loaded_secret}")

except ImportError as e:
    print(f"Error importing SecureConfig: {e}")
    print("Make sure you run this script from the project root directory ('bluep').")
except Exception as e:
    print(f"An error occurred: {e}")
