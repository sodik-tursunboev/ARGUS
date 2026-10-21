# Set up and build ARGUS

These instructions are for a Windows source checkout. Review the code and
security model before enabling host-control actions. No prebuilt or signed
installer is included.

## Prerequisites

- Windows with a Python 3 installation and PowerShell.
- Node.js and npm for the Svelte HUD.
- Git for obtaining the source.
- Ollama and the configured local model for model-assisted routing and chat.
- A microphone and audio output for voice features.

Some features need additional Windows permissions, browser binaries or
provider accounts. The Python and HUD dependency lists are in
requirements.txt, requirements.lock, hud-v2/package.json and
hud-v2/package-lock.json. The lock file at the repository root records
direct Python versions from the original installation; it is not a complete
transitive lock.

## Obtain and configure

~~~powershell
git clone https://github.com/sodik-tursunboev/ARGUS.git
Set-Location ARGUS
py -3 -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item config.example.py config.py
~~~

Open the local config.py and review paths and enabled capabilities. It is
ignored by Git. Set a command PIN with:

~~~powershell
.\venv\Scripts\python.exe manage_secrets.py set-pin
~~~

The command prints a salted hash to place in local config.py. Do not put the
PIN itself, generated hash, cloud keys or user paths in a commit. Follow the
instructions in manage_secrets.py for any optional owner-account enrollment.
For the default local model, install Ollama separately and obtain the model
named by OLLAMA_MODEL in config.py.

Voice model weights are not distributed in this repository. Place the
configured Piper model and companion files under a local voices/ directory,
or adjust PIPER_MODEL_PATH in local config.py. Other speech dependencies
may download their own models on first use.

## Build the HUD

~~~powershell
Set-Location hud-v2
npm ci
npm run build
npx tsc --noEmit
Set-Location ..
~~~

The generated hud-v2/dist directory is local build output and is ignored by
Git. The package build requires its entry and referenced assets. For HUD
development, run npm run dev from hud-v2; the local service still needs to
provide its API.

## Run from source

~~~powershell
.\venv\Scripts\python.exe argus.py
~~~

Start the app only in the Windows account intended to own its local data.
The service should remain bound to loopback. Optional browser automation
requires the Chromium installation described in requirements.txt. Optional
cloud, phone and messaging features require separate local configuration;
see [Phone setup](../PHONE.md) for Twilio.

## Build the Windows package

After the HUD is built and the local configuration and models are ready:

~~~powershell
.\venv\Scripts\python.exe -m pip install pyinstaller
.\venv\Scripts\python.exe build_exe.py
~~~

build_exe.py checks the HUD output and packages it with PyInstaller.
ARGUS.spec and lsass-helper.spec are build specifications. The separate
helper is optional and needs an elevated installation step on Windows.
Review the generated build before distribution. The public repository does
not include signing credentials.

## Local-only files

Keep config.py, config_secrets.py, the vault, token files, .env files,
logs, databases, voice weights, virtual environments and build output local.
The .gitignore covers these common paths. Before publishing a new snapshot,
inspect the actual staged file list and scan its content; Git history retains
anything committed by mistake unless that history is replaced.

See [Architecture](ARCHITECTURE.md) and [Security model](SECURITY_MODEL.md)
for how the application uses these components.
