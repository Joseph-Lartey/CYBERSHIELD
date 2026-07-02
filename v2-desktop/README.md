# CyberShield v2 — Windows Testing Guide

> **You do not need to be a programmer to follow this guide.**
> Every step is explained from scratch. If something goes wrong, there is a
> Troubleshooting section at the bottom.

---

## What is this?

CyberShield v2 is a ransomware detection tool that runs quietly in the background
on your Windows PC. It watches your files in real time and immediately stops any
program that starts behaving like ransomware — before your files get encrypted.

This guide will walk you through installing it and running a safe test to see it work.

---

## What you need

- A Windows PC (Windows 10 or Windows 11)
- An internet connection (to download the tools below)
- About 10 minutes

---

## Step 1 — Install Python

Python is the programming language CyberShield is written in.
Think of it like installing a translator that lets your PC run the program.

1. Open your web browser and go to: **https://www.python.org/downloads/**
2. Click the big yellow button that says **"Download Python 3.x.x"**
3. Run the installer that downloads
4. **IMPORTANT:** On the first screen of the installer, tick the box that says
   **"Add Python to PATH"** before clicking Install Now

   ```
   ☑  Add Python 3.x to PATH     ← TICK THIS BOX
   ```

5. Click **Install Now** and wait for it to finish
6. Click **Close**

**To check it worked:**
Press the `Windows key + R`, type `cmd`, press Enter.
A black window (the terminal) will open. Type:
```
python --version
```
You should see something like `Python 3.12.0`. If you do, Python is installed.

---

## Step 2 — Download CyberShield

**Option A — If you have Git installed:**
```
git clone https://github.com/Joseph-Lartey/CYBERSHIELD.git
```

**Option B — Download as a ZIP (easier):**
1. Go to the GitHub page for this project
2. Click the green **"Code"** button
3. Click **"Download ZIP"**
4. Right-click the downloaded ZIP file and choose **"Extract All"**
5. Remember where you extracted it (e.g. `C:\Users\YourName\Downloads\CYBERSHIELD`)

---

## Step 3 — Open the terminal in the right folder

1. Open **File Explorer** and navigate to the folder you just extracted
2. Open the `v2-desktop` folder inside it
3. Click on the address bar at the top of File Explorer (it shows the folder path)
4. Type `cmd` and press Enter

   ```
   Before: C:\Users\YourName\Downloads\CYBERSHIELD\v2-desktop
   Type:   cmd
   Press:  Enter
   ```

A black terminal window will open, already pointing at the right folder.
You will see something like:
```
C:\Users\YourName\Downloads\CYBERSHIELD\v2-desktop>
```

---

## Step 4 — Install the dependencies

Dependencies are the extra tools CyberShield needs to run.
In the terminal, copy and paste this line exactly, then press Enter:

```
pip install -r requirements.txt
```

You will see a lot of text scrolling past — this is normal. It is downloading
and installing the required tools. Wait until it finishes and you see the
`>` prompt again.

This may take 1–2 minutes depending on your internet speed.

---

## Step 5 — Run the agent

**Important: Run the terminal as Administrator.**

Close the terminal you just opened. Now:

1. Press `Windows key`, type `cmd`
2. Right-click **Command Prompt** in the results
3. Click **"Run as administrator"**
4. Click **Yes** when Windows asks for permission
5. Navigate back to your folder by typing (replace the path with your actual path):
   ```
   cd C:\Users\YourName\Downloads\CYBERSHIELD\v2-desktop
   ```
6. Now start the agent:
   ```
   python agent/agent.py
   ```

You should see output like this:
```
14:32:01  INFO      cybershield.agent  ============================================================
14:32:01  INFO      cybershield.agent    CyberShield v2 — Ransomware Detection Agent
14:32:01  INFO      cybershield.agent  ============================================================
14:32:01  INFO      cybershield.honey  Honey file planted: C:\Users\YourName\!!AAAA_cybershield_canary.txt
14:32:01  INFO      cybershield.honey  Honey file planted: C:\Users\YourName\Desktop\!!AAAA_cybershield_canary.txt
14:32:02  INFO      cybershield.agent  Monitoring paths: ['C:\\Users\\YourName']
14:32:02  INFO      cybershield.agent  Agent running. Press Ctrl+C to stop.
```

**The agent is now running.** Leave this terminal window open.

---

## Step 6 — Run the safe test

Now open a **second** terminal window (you can leave the agent running in the first one):

1. Press `Windows key + R`, type `cmd`, press Enter
2. Navigate to the same folder:
   ```
   cd C:\Users\YourName\Downloads\CYBERSHIELD\v2-desktop
   ```
3. Run the test simulator:
   ```
   python tests/simulate_ransomware.py
   ```

You will see:
```
=======================================================
  CyberShield — Safe Ransomware Behaviour Simulator
=======================================================

⚠️  Make sure the CyberShield agent is running first!

Press ENTER when the agent is running to start the simulation...
```

Press Enter to start.

---

## Step 7 — Watch the agent react

Switch back to the **first** terminal (where the agent is running).

Within a few seconds of the test starting, you should see alerts appearing:

```
14:32:45  WARNING   cybershield.file_monitor  Mass write activity: 25 writes in 5s
14:32:45  WARNING   cybershield.agent         ⚠️  HIGH THREAT — mass_write — 25 file writes in 5s
14:32:46  WARNING   cybershield.file_monitor  Known ransomware extension detected: {'.locked'}
14:32:46  CRITICAL  cybershield.agent         🚨 CRITICAL THREAT — ransom_extension — Files renamed to: {'.locked'}
14:32:46  WARNING   cybershield.entropy       High entropy file detected: ...document_001.locked (entropy=7.943)
14:32:46  WARNING   cybershield.response_engine  ResponseEngine handling: type=ransom_extension severity=critical
```

You will also see a **desktop notification** pop up in the bottom-right corner of your screen.

---

## What do the alerts mean?

| Alert | What it means |
|---|---|
| `mass_write` | Too many files were written in a short time — ransomware behaviour |
| `ransom_extension` | Files were renamed with a known ransomware extension like `.locked` |
| `high_entropy_file` | A file's contents look like encrypted data (random, unreadable) |
| `honey_file_triggered` | A decoy file was touched — the most serious signal |

---

## Where are the logs?

After running the test, CyberShield will have created a log file at:
```
v2-desktop\logs\incidents.jsonl
```

You can open this with Notepad. Each line is a complete record of one detected threat,
including what type it was, how severe, and what action was taken.

---

## How to stop the agent

Go back to the first terminal (where the agent is running) and press:
```
Ctrl + C
```

The agent will shut down cleanly:
```
14:45:00  INFO  cybershield.agent  Shutdown signal received — stopping agent...
14:45:00  INFO  cybershield.agent  Agent shut down cleanly.
```

---

## Troubleshooting

### "python is not recognized as a command"
You did not tick "Add Python to PATH" during installation.
Uninstall Python, reinstall it, and make sure to tick that box.

### "pip is not recognized as a command"
Python installed without pip. Run:
```
python -m ensurepip --upgrade
```
Then try `pip install -r requirements.txt` again.

### "Access is denied" or "Permission error"
The agent needs Administrator permissions to monitor processes.
Make sure you right-clicked Command Prompt and chose "Run as administrator".

### "ModuleNotFoundError: No module named 'watchdog'"
The dependencies did not install correctly. Run:
```
pip install watchdog psutil flask colorama
```

### The agent runs but I see no alerts during the test
Make sure both terminals are pointing at the same `v2-desktop` folder.
Check that the agent output shows `Agent running` before you start the test.

### "No honey files planted"
This is harmless — it just means one of the target directories (Desktop, Documents)
did not exist. The file monitor is still active.

---

## What was actually tested?

The simulator did three things that real ransomware does:

1. **Wrote 30 files rapidly** — triggered the mass-write detector
2. **Renamed them all to `.locked`** — triggered the known-extension detector
3. **Overwrote them with random data** — triggered the entropy detector

None of these actions harmed your real files. The simulator only touched
files it created itself in a dedicated test folder on your Desktop,
which it offers to clean up at the end.

---

## Summary

```
Terminal 1 (Admin):   python agent/agent.py          ← the guard
Terminal 2 (Normal):  python tests/simulate_ransomware.py  ← the test attack
```

CyberShield detected all three ransomware behaviours — mass writes,
known extensions, and encrypted-looking file contents — and logged
a full incident record for each one.
