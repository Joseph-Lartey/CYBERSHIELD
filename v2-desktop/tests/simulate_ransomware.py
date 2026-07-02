"""
Safe Ransomware Simulator — FOR TESTING ONLY
---------------------------------------------
This script mimics what ransomware does to the file system WITHOUT
actually being malicious. It:
  1. Creates dummy files in a test folder on your Desktop
  2. Rapidly renames them with a .locked extension
  3. Writes high-entropy (random) data into them
  4. Cleans up after itself

Run this in a second terminal WHILE the agent is running to test detection.
This script is 100% safe — it only touches files it creates itself.
"""

import os
import sys
import time
import random
import string
import shutil
from pathlib import Path

TEST_FOLDER = Path.home() / "Desktop" / "CYBERSHIELD_TEST"
NUM_FILES = 30       # how many fake files to create
WRITE_DELAY = 0.05   # seconds between writes (lower = more aggressive)


def create_test_files():
    TEST_FOLDER.mkdir(exist_ok=True)
    print(f"[*] Creating {NUM_FILES} test files in {TEST_FOLDER} ...")
    for i in range(NUM_FILES):
        filepath = TEST_FOLDER / f"document_{i:03d}.txt"
        with open(filepath, "w") as f:
            f.write(f"This is a fake document number {i}.\n" * 20)
    print(f"[+] {NUM_FILES} files created.")


def simulate_mass_rename():
    print("\n[*] Simulating mass rename (like ransomware adding .locked extension)...")
    files = list(TEST_FOLDER.glob("*.txt"))
    for i, filepath in enumerate(files):
        new_path = filepath.with_suffix(".locked")
        filepath.rename(new_path)
        print(f"    Renamed: {filepath.name} → {new_path.name}")
        time.sleep(WRITE_DELAY)
    print(f"[+] Renamed {len(files)} files to .locked")


def simulate_high_entropy_writes():
    print("\n[*] Simulating encrypted file writes (high entropy data)...")
    files = list(TEST_FOLDER.glob("*.locked"))
    for filepath in files:
        # Write random bytes — this looks like encrypted content
        with open(filepath, "wb") as f:
            f.write(os.urandom(4096))
        time.sleep(WRITE_DELAY)
    print(f"[+] Wrote random data to {len(files)} files.")


def cleanup():
    print(f"\n[*] Cleaning up test folder: {TEST_FOLDER}")
    if TEST_FOLDER.exists():
        shutil.rmtree(TEST_FOLDER)
    print("[+] Cleanup done.")


def main():
    print("=" * 55)
    print("  CyberShield — Safe Ransomware Behaviour Simulator")
    print("=" * 55)
    print("\n⚠️  Make sure the CyberShield agent is running first!")
    print("   Open a separate terminal and run: python agent/agent.py\n")

    input("Press ENTER when the agent is running to start the simulation...")

    try:
        create_test_files()
        time.sleep(1)

        simulate_mass_rename()
        time.sleep(1)

        simulate_high_entropy_writes()

        print("\n✅ Simulation complete.")
        print("   Check the agent terminal — you should see threat alerts.")
        print(f"   Check logs/incidents.jsonl for the logged incident.")

    except KeyboardInterrupt:
        print("\n[!] Simulation interrupted.")
    finally:
        answer = input("\nClean up test files? (y/n): ").strip().lower()
        if answer == "y":
            cleanup()
        else:
            print(f"Test files left at: {TEST_FOLDER}")


if __name__ == "__main__":
    main()
