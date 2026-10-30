# Passport Prime Hackathon: Laptop Setup

Welcome! At the hackathon you'll build an app for **Passport Prime** using the **KeyOS SDK**. Please set up your laptop **before the event**. The first install downloads a toolchain and the first build compiles a lot of code, which is slow on conference Wi-Fi.

**You need:**

- A laptop running **macOS** (Apple Silicon or Intel), **Linux** (x86_64 or ARM64), or **Windows 10/11 with WSL2**
- An internet connection and a few GB of free disk space (the SDK alone is about 700 MB, plus the Nix toolchain)
- A coding agent such as Claude Code or Codex is strongly recommended. The SDK is built to work with one.
- **No Passport Prime is needed.** Everything runs in the KeyOS simulator on your laptop.

The installer currently installs **KeyOS SDK v1.1.0**.

---

## Step 1: Install the prerequisites

<details open>
<summary><b>macOS</b></summary>

Install Git (part of Apple's command line tools):

```bash
xcode-select --install
```

Install GPG, which the SDK installer uses to verify its download. This uses [Homebrew](https://brew.sh); install that first if you don't have it.

```bash
brew install gnupg
```

</details>

<details open>
<summary><b>Linux</b></summary>

Most distributions already have these. If not, on Debian or Ubuntu:

```bash
sudo apt update && sudo apt install -y curl git gnupg
```

On Fedora:

```bash
sudo dnf install -y curl git gnupg2
```

</details>

<details open>
<summary><b>Windows</b></summary>

The SDK runs inside WSL2 (Windows Subsystem for Linux). Open **PowerShell as administrator** and run:

```powershell
wsl --install
```

Restart when asked, then open **Ubuntu** from the Start menu and create your Linux user. Make sure WSL is current so it can open Linux app windows (the simulator is one):

```powershell
wsl --update
```

From here on, run **every command inside the Ubuntu terminal** and follow the Linux steps, starting with:

```bash
sudo apt update && sudo apt install -y curl git gnupg
```

</details>

---

## Step 2: Install Nix

The SDK uses [Nix](https://nixos.org) to provide the Rust toolchain, cross-compiler, simulator and signing tools, so you don't install any of those yourself. Use the Determinate Systems installer.

**macOS:** the easiest option is the graphical installer. [Download Determinate Nix](https://install.determinate.systems/determinate-pkg/stable/Universal) and run it. More details are at [docs.determinate.systems](https://docs.determinate.systems/).

**macOS, Linux and WSL (command line):**

```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

When it finishes, **close your terminal and open a new one.**

> **WSL tip:** if the Nix install fails because systemd isn't running, either enable systemd (add `[boot]` and `systemd=true` to `/etc/wsl.conf`, then run `wsl --shutdown` in PowerShell and reopen Ubuntu), or install without it:
>
> ```bash
> curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install linux --init none
> ```
>
> See the [Determinate installer's WSL notes](https://github.com/DeterminateSystems/nix-installer#in-wsl2) for more.

---

## Step 3: Install the KeyOS SDK

```bash
curl -sSfL https://sdk.foundation.xyz/latest/install.sh | bash
```

Close your terminal and open a new one (or follow the `PATH` instructions the installer prints), then check your setup:

```bash
foundation doctor
```

Fix anything `doctor` reports before moving on. If it says Nix is missing, go back to Step 2 and open a fresh terminal.

> On NixOS, or if Home Manager manages your shell config, install with `FOUNDATION_SDK_UPDATE_RC=0` before `bash` and add `~/.foundation/sdk/bin` to your `PATH` yourself.

---

## Step 4: Do a warm-up build

This is the step that saves you the most time at the event. Enter the SDK shell, create a test app, and run it in the simulator:

```bash
foundation develop
foundation new hello-prime
cd hello-prime
foundation sim
```

- The first `foundation develop` downloads the toolchain, so give it a while.
- `foundation new` asks a few questions. Pressing Enter to accept the defaults is fine.
- The first `foundation sim` compiles every dependency. When a Passport Prime screen appears in a window, you're ready.

---

## Step 5 (recommended): Set up your coding agent

Every app made with `foundation new` already includes an `AGENTS.md` and SDK skills for Claude Code and Codex. **Start your agent from a terminal where you've run `foundation develop`**, inside your app folder.

To let your agent see and drive the **simulator** (take screenshots, tap, swipe and type), replace the app's `.mcp.json` with:

```json
{
  "mcpServers": {
    "passport-sim": {
      "type": "stdio",
      "command": "foundation-passport-drive",
      "args": ["--sim", "mcp"]
    },
    "passport-drive": {
      "type": "stdio",
      "command": "foundation-passport-drive",
      "args": ["mcp"]
    }
  }
}
```

`passport-sim` drives a running `foundation sim`. `passport-drive` drives a real Passport Prime over USB.

A good first prompt:

```text
Build a two-page KeyOS app for tracking recovery checks.
Use the SDK's existing Slint components.
Preview the UI, then run the complete app in the simulator.
Don't create signing keys or use connected hardware without asking me first.
```

---

## Troubleshooting

| Problem | Fix |
| --- | --- |
| Installer says **gpg is not installed** | Install GPG (Step 1), then run the installer again. |
| `foundation: command not found` | Open a new terminal, or add the `PATH` line the installer printed to your shell config. |
| `foundation doctor` says **Nix is missing** | Finish Step 2, then open a new terminal. |
| The simulator window doesn't appear on Windows | Run `wsl --update` in PowerShell, then `wsl --shutdown`, and reopen Ubuntu. |
| Linux: **permission denied** talking to a real Passport over USB | Only needed for hardware: `sudo cp ~/.foundation/sdk/current/share/99-passport.rules /etc/udev/rules.d/ && sudo udevadm control --reload && sudo udevadm trigger` |

---

## Useful links

- Developer documentation: <https://docs.foundation.xyz/developers/home/>
- Full API reference, offline: run `foundation docs`

---

## Developer units vs. production

Passport Prime developer units differ from production units in one important way: **the screen is removable.**

- Taking the screen off triggers a **tamper**, the same thing that happens if an attacker tries to open the device. That lets you test how your app handles a tamper.
- Data your app keeps in its private storage is included automatically in the encrypted **Magic Backup**.
- After a tamper and restore, make sure your app comes back in the right state.
- Keep the screen on with a rubber band or a **Passport Prime bumper case**, so it doesn't tamper by accident.

**Attended the hackathon?** Email [ken@foundation.xyz](mailto:ken@foundation.xyz) for a free bumper case.

---

See you at the hackathon, and bring your laptop!