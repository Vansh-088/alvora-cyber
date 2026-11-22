# Alvora Cyber — Launch Readiness

_Assessed 2026-10-23 against desktop app v1.1.2 and extension v1.1.1._

## Recommendation

**Don't submit to the Mac App Store yet — and probably not at all for the full product.**
Test privately for 3–4 more weeks, then launch as a **notarized direct download**
from alvoracyber.com. This is how most serious Mac security tools ship
(Malwarebytes, Objective-See's LuLu/BlockBlock, Little Snitch) because of the
sandbox problem below.

## Why the Mac App Store doesn't fit (today)

Every Mac App Store app must run inside Apple's **App Sandbox** (App Review
Guideline 2.4.5). The sandbox blocks most of what makes Alvora useful:

| Alvora feature | What it needs | Allowed in the sandbox? |
|---|---|---|
| Security Check (FileVault, firewall, sharing…) | Runs `fdesetup`, `socketfilterfw`, `sysadminctl`, `netstat` | No — can't launch system tools this way |
| Network monitor (which app talks to whom) | `lsof` on other apps' connections | No — can't see other processes |
| Startup-item monitor | Reads `~/Library/LaunchAgents`, `/Library/LaunchDaemons` | No — outside the app's container |
| Signature checks on running apps | Runs `codesign` on other apps' binaries | No |
| Downloads scanner | Watches `~/Downloads` continuously | Only files the user picks each time |
| Browser extension link | Local server on `127.0.0.1:3001` | Possible, but fragile and heavily reviewed |
| Local AI (Ollama) | Talks to another local app | Possible with network entitlements |

A sandboxed "App Store edition" would keep little more than the AI prompt
scanner and Link Guard. That's a different, much smaller product — worth
considering later as a lead-in, not as the main app.

## Before a public launch (direct download)

Must-have:
- [ ] **Notarization** — the build is signed but not notarized, so other people
      see Apple's "can't verify this app" warning. The `alvora-notary` keychain
      profile already exists; drop `SKIP_NOTARIZE=1` for release builds.
- [ ] **Auto-updates** — wire up `electron-updater` (the GitHub publish config is
      already in `electron-builder.json`) so security fixes reach users.
- [ ] **Privacy policy + terms on alvoracyber.com** — must disclose: optional
      cloud AI providers (OpenRouter, NVIDIA, Anthropic) receive text when the
      user enables them; threat-intel feeds are downloaded; nothing else leaves
      the Mac; beta signup collects name + email.
- [ ] **First-run permissions screen** — explain and request Downloads-folder
      access instead of relying on the system prompt appearing mid-use.
- [ ] **Quieter alerts** — during testing, developer tools (e.g. `npm exec …`)
      are reported as "Unsigned program using the internet". Add an "I trust
      this" action and smarter defaults so real users aren't trained to ignore
      alerts.
- [ ] **Uninstall instructions** (or an uninstall button) that also removes the
      login item and `~/Library/Application Support/Alvora Cyber`.
- [ ] **Intel Macs** — current builds are Apple-silicon only (`arm64`). Ship a
      universal build or state the requirement on the download page.

Nice-to-have:
- [ ] Opt-in crash reporting so bugs from testers reach you.
- [ ] Chrome Web Store listing for the extension (needs its own privacy policy
      and a justification for the `webNavigation` permission).
- [ ] Support email and a short FAQ on the website.

## Testing plan (next 3–4 weeks)

1. Use it daily on your own Mac; note every alert that wasn't useful.
2. Give the notarized build to 3–5 friends on different Macs (Intel if
   possible, different macOS versions) and collect their Security Check results.
3. Watch for: false alarms, slowdowns, battery drain, anything confusing.
4. Fix, then launch.
