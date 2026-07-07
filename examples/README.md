# Try Stele — a complete walkthrough (no experience needed)

This walks you through running a real, working sign-in system on your own computer, using passkeys (Face ID / Touch ID / your phone) instead of a password. It takes about 10 minutes.

You'll be pasting commands into the Terminal app. Copy each block exactly as shown, paste it in, press Enter, and wait for it to finish before moving to the next one.

## Before you start

You need three things installed. If you already have them, skip ahead.

**1. Docker Desktop** — this runs the database.
Download it from https://www.docker.com/products/docker-desktop/ and install it like any other Mac app. Open it once from your Applications folder and leave it running in the background (you'll see a whale icon in your menu bar).

**2. Python** — version 3.12 or newer.
Download it from https://www.python.org/downloads/ and install it like any other Mac app.

**3. Terminal** — already on your Mac.
Open it: press Cmd+Space, type "Terminal", press Enter.

Check both installed correctly by pasting this into Terminal:

```
docker --version
python3 --version
```

You should see a version number printed for each (Docker 24 or higher, Python 3.12 or higher). If either command says "not found," go back and reinstall it. If `python3 --version` prints something *older* than 3.12 even though you just installed a newer one, see "If something goes wrong" below before continuing.

## Step 1 — Get the code

If you were sent a link to a public GitHub repository, open it in your browser, click the green "Code" button, then "Download ZIP." Unzip it — you'll get a folder, probably named `stele-main` or `stele`. Drag that folder to your Desktop and rename it `stele` (optional, just makes the next steps easier to read).

If you already have `git` and were given repo access, you can instead run:
```
cd ~/Desktop
git clone https://github.com/DUNIN7/stele.git
```

Either way, you should now have a `stele` folder on your Desktop.

## Step 2 — Move into the project and start the database

Paste this whole block into Terminal:

```
cd ~/Desktop/stele/examples
docker compose up -d
```

Wait about 10 seconds. You should see output ending in something like `Container examples-postgres-1  Started`. This started a small database running only inside Docker — it doesn't touch anything else on your computer, and you can throw it away later with no side effects.

## Step 3 — Set up a clean Python environment and install everything

```
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e "..[examples]"
```

This last command takes 20-60 seconds and prints a lot of text — that's normal. When it finishes, you'll see a line ending in `Successfully installed ...`.

**Important:** keep this same Terminal window open for every remaining step. If you close it or open a new one, you'll need to run `cd ~/Desktop/stele/examples && source .venv/bin/activate` again first.

## Step 4 — Create your configuration file

Still in the same Terminal window:

```
python3 generate_env.py > .env
```

Nothing prints — that's correct. This created a hidden file (`.env`) with a fresh, randomly generated security key and default settings. You don't need to open or edit it.

## Step 5 — Load your configuration into this Terminal session

```
set -a
. ./.env
set +a
```

Nothing visible happens — that's correct.

## Step 6 — Create the database tables

This one step happens from a different folder — the one directly above `examples`:

```
cd ..
alembic upgrade head
```

You should see two lines mentioning `0001_baseline` and `0002_totp_last_step`, ending in something like `Running upgrade ... -> 0002_totp_last_step, ...`. This created the actual tables the app needs.

## Step 7 — Start the app

```
cd examples
uvicorn reference_app.main:app --reload --port 8000
```

You should see a line ending in `Application startup complete.` Leave this Terminal window open and running — it's your live server.

## Step 8 — Try it

Open your web browser and go to:

```
http://localhost:8000
```

You'll see a simple sign-up page. Click sign up, give yourself a name, and follow your Mac's prompt to use Touch ID (or your phone, if given the option) instead of a password. You'll then see a screen with 10 recovery codes — these are your backup if you ever lose access to Touch ID. Take a screenshot or write them down.

Sign out, then sign back in. Notice there's no email address or username to type anywhere — your Mac just offers your passkey, you approve it, and you're in. That's the whole point of Stele.

## When you're done

Go back to the Terminal window running the server and press Control+C to stop it. To remove the database entirely:

```
cd ~/Desktop/stele/examples
docker compose down -v
```

---

## If something goes wrong

**"command not found: docker" or "command not found: python3"**
Go back to "Before you start" — one of the two installs didn't finish. Restart Terminal after installing and try again.

**"python3 --version" shows something older than 3.12, even after installing Python 3.12+**
Your Mac likely already had an older Python installed, and `python3` still points at that one instead of the version you just installed. Use `python3.12` explicitly when creating the virtual environment in Step 3:
```
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e "..[examples]"
```
Everything from here on runs inside that environment, so the rest of the guide works unchanged — you only need `python3.12` for this one command.

**Step 3 prints an error mentioning "no matches found"**
You likely typed `pip install -e ..[examples]` without the quotation marks. Use exactly `pip install -e "..[examples]"`, including the quotes.

**Step 6 (`alembic upgrade head`) fails with "No 'script_location' key found"**
You ran it from the wrong folder. Make sure you ran `cd ..` first, so you're in the `stele` folder, not `stele/examples`.

**Signing up in Step 8 fails with a generic error**
Almost always means Step 6 was skipped or failed silently. Go back and confirm Step 6 printed the two migration lines before continuing.

**You closed the Terminal window partway through**
Open a new one and run this before continuing from where you left off:
```
cd ~/Desktop/stele/examples
source .venv/bin/activate
set -a
. ./.env
set +a
```
