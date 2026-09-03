# deathstr0ke — how it behaves

This describes what deathstr0ke does from a user's point of view: how it responds to passwords, what
protects you, and how to set it up and recover. It intentionally does not describe internal mechanisms.

## What it protects

deathstr0ke guards an encrypted machine against being unlocked by someone who has taken it. It responds
to how passwords are entered, at the boot prompt and at every login screen.

## Password behavior

- **Your passphrase** unlocks the machine normally.
- **A wrong passphrase, repeated:** after a few consecutive wrong attempts the machine warns you that
  further failures will destroy it, then slows each further attempt down. Continued failures make the
  data permanently unrecoverable.
- **Any correct entry clears the count.** A normal mistake followed by a successful login resets
  everything, so ordinary fat-fingering is harmless.
- **A duress code** (optional, set by you) looks like a normal login but immediately makes the data
  permanently unrecoverable. Use it if you are forced to unlock the machine. It never grants access and
  has no warning or limit.

These apply at the boot unlock prompt, the desktop greeter, the lock screen, and terminal password
prompts. Once triggered, the outcome cannot be stopped, reversed, or recovered without your recovery
factor.

## Optional protections you can enable

- **Hardware key (recommended):** register a security key so the machine also unlocks with a tap.
  Register a backup key as well.
- **Dead-man switch:** the machine wipes itself if you do not check in within a window you choose (for
  example, once a day). Any successful login counts as a check-in. This protects a machine that is
  taken and set aside for later analysis.
- **Stronger key protection:** raise the effort required to guess your passphrase, at the cost of a
  slightly slower unlock.

## Setup

1. Set a recovery factor first so you can never be permanently locked out (a passphrase you will
   remember, plus a backup security key). Store the backup key somewhere safe and separate.
2. Optionally set a duress code.
3. Optionally enable the dead-man switch and register a hardware key.
4. Arm it. You can disarm at any time; while disarmed, the machine behaves like a normal encrypted
   system with no idle cost.

## Recovery

- **Forgot the passphrase, or lost a hardware key:** use your other registered factor (the passphrase
  or the backup key). This also brings you back if a partial protection step ran.
- **After a full destruction (wrong-limit reached, or duress):** this is permanent by design. There is
  no backdoor and no vendor recovery. That permanence is the point.

## What it does not claim to do

deathstr0ke is honest about its limits. It strongly protects a machine that is taken and then someone
tries to unlock it. It does not promise to defeat every possible attack on hardware you no longer
control. Choose your passphrase strength and optional protections according to your own threat model.

---

Part of the ArxOS project.
