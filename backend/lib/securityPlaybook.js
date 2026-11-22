/**
 * securityPlaybook.js — checked reference notes for Alvora AI.
 *
 * Small local models give much better advice when the right facts are in
 * front of them, and they invent menu paths when they aren't. These notes
 * (macOS 15+ System Settings names) are matched to the question by keyword
 * and passed along as reference material.
 */

// Where things are inside Alvora — always included
export const APP_MAP = `Where things are in Alvora Cyber (left sidebar):
- Dashboard: "Run Security Check", the 0–100 score, and "How to fix these" / "See all checks" with step-by-step fixes.
- Alvora AI: this chat.
- AI Monitor: paste any text to check it for personal data and prompt-injection attacks.
- Firewall: which apps use the internet (network monitor), threat-intelligence lists, and Link Guard (phishing-link blocking used by the browser extension).
- Kernel: this Mac's security settings, the Downloads scanner, and Startup Items (things set to run automatically).
- Threat Map: where flagged connections are located.
- Reports: alert history and statistics.
- Vault: encrypted storage for sensitive files.
- Settings: Your Data (clear history, how long to keep it, trusted apps and addresses), AI provider keys, notifications.
- On any alert: "Trust … — stop alerting" (for something you know is fine) or "Dismiss this alert".
- Browser extension: warns before personal data or prompt-injection is sent to AI chat sites ("Redact & Send"), and blocks known phishing links.`;

const NOTES = [
  {
    keys: /wi-?fi|wifi|public network|hotspot|caf[eé]|hotel|airport|coffee|vpn/i,
    text: `Public Wi-Fi:
- Keep the firewall on and turn on stealth mode: System Settings → Network → Firewall → Options → "Enable stealth mode". It hides the Mac from others on the network.
- Turn off File Sharing, Screen Sharing and Remote Login: System Settings → General → Sharing.
- Set AirDrop to Contacts Only: System Settings → General → AirDrop & Handoff.
- Use a private address: System Settings → Wi-Fi → Details next to the network → Private Wi-Fi address → Rotating or Fixed.
- Only sign in to sites that show https. For banking, prefer your phone's hotspot or a reputable paid VPN.
- Afterwards, forget the network so the Mac doesn't rejoin it automatically.`,
  },
  {
    keys: /password|passkey|login|credential|keychain|reuse|leak|breach|pwned/i,
    text: `Passwords:
- Use a different password for every account. Let the Passwords app (or a password manager) create and remember them.
- Check for leaked or reused passwords: open the Passwords app → Security.
- Prefer passkeys where a site offers them — they can't be phished.
- Turn on two-factor authentication for email, Apple Account, bank and social accounts.
- Never type a password into a page you reached from an email or message link; go to the site yourself.`,
  },
  {
    keys: /2fa|two.?factor|mfa|authenticat|verification code|one.?time code/i,
    text: `Two-factor authentication:
- Apple Account: System Settings → your name → Sign-In & Security → Two-Factor Authentication.
- Elsewhere, use an authenticator app or passkeys rather than SMS codes where possible.
- Nobody legitimate will ever ask you to read a verification code back to them.`,
  },
  {
    keys: /phish|scam|fake|suspicious (email|link|message)|link|email|sms|text message|smish/i,
    text: `Phishing:
- Warning signs: urgency or threats, a sender address that doesn't match the company, requests for codes or passwords, unexpected attachments, links whose real address differs from the text.
- Don't click — open the company's site or app yourself to check.
- Alvora's browser extension blocks known phishing sites; Safari also warns: Safari → Settings → Security → "Warn when visiting a fraudulent website".
- If you already entered a password, change it now (from a trusted device) and turn on two-factor authentication.`,
  },
  {
    keys: /update|patch|outdated|old version|software update/i,
    text: `Updates:
- System Settings → General → Software Update → ⓘ next to Automatic updates: turn on everything, especially "Install Security Responses and system files".
- Update apps too: App Store → Updates, and each browser's own updater.
- Restart when asked — many fixes only apply after a restart.`,
  },
  {
    keys: /backup|time machine|ransom|lost (my )?files|recover/i,
    text: `Backups:
- Time Machine: System Settings → General → Time Machine → Add Backup Disk, and tick "Encrypt Backup".
- Keep at least one backup disconnected when not in use, so ransomware can't reach it.
- iCloud Drive syncing is not a full backup — deleted or encrypted files sync too.`,
  },
  {
    keys: /malware|virus|hack|infect|compromis|trojan|spyware|keylogger|ransom|weird|slow|pop.?up/i,
    text: `If you suspect malware:
- Disconnect from the internet first.
- Run a Security Check on the Dashboard, then look at Kernel → Startup Items and Firewall for anything unfamiliar.
- Check System Settings → General → Login Items & Extensions and remove what you don't recognise.
- Delete apps you didn't install on purpose (drag from Applications to Trash).
- Change important passwords from a different, trusted device.
- For ransom notes: don't pay; get professional help; restore from a backup made before the problem.`,
  },
  {
    keys: /stolen|lost (my )?(mac|laptop)|find my|theft/i,
    text: `Lost or stolen Mac:
- Before it happens: turn on FileVault and Find My Mac (System Settings → your name → iCloud → Find My Mac).
- If it's gone: use icloud.com/find or the Find My app on another device to locate, lock or erase it, then change your Apple Account password.`,
  },
  {
    keys: /camera|microphone|mic\b|screen record|privacy|permission|track|spy/i,
    text: `App permissions:
- Review System Settings → Privacy & Security → Camera, Microphone, Screen & System Audio Recording, Full Disk Access, Accessibility.
- Remove access from anything you don't use or don't recognise.
- The green/orange dot in the menu bar shows when the camera/microphone is in use.`,
  },
  {
    keys: /filevault|encrypt|disk/i,
    text: `FileVault: System Settings → Privacy & Security → FileVault → Turn On. Save the recovery key somewhere safe (iCloud is easiest). Encryption runs in the background.`,
  },
  {
    keys: /firewall|stealth|incoming|port/i,
    text: `Firewall: System Settings → Network → Firewall → on. Options → "Enable stealth mode" for extra protection on shared networks. Alvora's Firewall tab shows which apps actually use the internet.`,
  },
  {
    keys: /bluetooth|airdrop|handoff/i,
    text: `AirDrop & Bluetooth: set AirDrop to Contacts Only (System Settings → General → AirDrop & Handoff). Turn Bluetooth off in public if you don't need it.`,
  },
  {
    keys: /browser|extension|chrome|safari|firefox|cookie/i,
    text: `Browsers:
- Remove extensions you don't use; extensions can read the pages you visit.
- Keep the browser updated and let it warn about dangerous sites.
- Alvora's own extension adds AI-chat protection and phishing-link blocking.`,
  },
  {
    keys: /\bai\b|chatgpt|claude|gemini|prompt|injection|chatbot|llm/i,
    text: `Using AI chatbots safely:
- Don't paste passwords, card numbers, ID numbers or confidential work data into AI chats.
- Alvora's browser extension warns before you send personal data, and "Redact & Send" replaces it with placeholders.
- Be wary of documents, emails or web pages you ask an AI to summarise — they can contain hidden instructions ("prompt injection"). AI Monitor can check text for this.`,
  },
  {
    keys: /score|improve|better|harden|secure (my )?mac|what should i do|next step|checklist/i,
    text: `Raising the score: open Dashboard → "How to fix these" — issues are listed biggest gain first, each with steps and a shortcut to the right System Settings page. Re-check afterwards. At 100/100, keep automatic updates on, use unique passwords with two-factor authentication, keep a backup, and be careful with links and downloads.`,
  },
];

/** The reference notes most relevant to the conversation (newest question weighted most). */
export function notesFor(messages, max = 3) {
  const users = messages.filter(m => m.role === 'user').map(m => m.content);
  const latest = users[users.length - 1] ?? '';
  const earlier = users.slice(-3, -1).join(' ');
  const scored = NOTES
    .map(n => ({ n, score: (n.keys.test(latest) ? 2 : 0) + (n.keys.test(earlier) ? 1 : 0) }))
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, max);
  return scored.map(x => x.n.text);
}
