/**
 * Alvora Cyber — Prompt Injection & Adversarial AI Guard
 *
 * Detects prompt injection attacks, jailbreak attempts, role-override
 * exploits, and system prompt exfiltration — the core threats in
 * AI-mediated attack surfaces.
 *
 * This module is Alvora's primary IP: the detection layer that sits
 * between a user's input and any LLM API call.
 *
 * PLUG-IN POINT: Add domain-specific patterns for enterprise deployments
 * (e.g., financial services, healthcare, legal) as premium tiers.
 */

// ─── Detection Rule Registry ──────────────────────────────────────────────────

const RULES = [

  // ══ CRITICAL: Direct control injection ════════════════════════════════════════
  {
    id:       'INJ-001',
    name:     'Someone tried to override your AI\'s rules',
    severity: 'CRITICAL',
    category: 'AI Hijack Attempt',
    description: 'A message tried to make the AI ignore its safety rules and do whatever the attacker says.',
    patterns: [
      /ignore\s+(all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|system|context)/gi,
      /disregard\s+(?:all\s+)?(?:previous|prior|your|the)\s+/gi,
      /forget\s+(?:everything|all|your|the\s+previous)/gi,
      /override\s+(?:your|all|the)\s+(?:instructions?|system|rules?|guidelines?)/gi,
    ],
  },
  {
    id:       'INJ-002',
    name:     'Someone tried to unlock a "no rules" mode',
    severity: 'CRITICAL',
    category: 'AI Hijack Attempt',
    description: 'A known trick (like "DAN" or "jailbreak") that tries to switch the AI into an unsafe mode with no limits.',
    patterns: [
      /\bDAN\b/g,
      /jailbreak/gi,
      /\bdeveloper\s*mode\b/gi,
      /god\s*mode/gi,
      /\bunrestricted\s+mode\b/gi,
      /bypass\s+(?:safety|filter|restriction|guard|content|policy|rule)/gi,
      /disable\s+(?:all\s+|the\s+)?(?:safety|content|security|moderation)\s+(?:filter|guard|check|rule|restriction|guideline|policy)s?/gi,
      /(?:turn\s+off|remove|drop)\s+(?:all\s+|your\s+)?(?:safety|content|guard|restriction|filter|guideline)s?/gi,
      /enable\s+(?:unsafe|uncensored|unfiltered|unrestricted)\s+mode/gi,
      /do\s+anything\s+now/gi,
      /\bSAIL\b|\bSTAN\b|\bAIM\b/g, // common DAN variants
    ],
  },
  {
    id:       'INJ-003',
    name:     'Someone tried to change who your AI pretends to be',
    severity: 'CRITICAL',
    category: 'AI Hijack Attempt',
    description: 'A message tried to make the AI take on a fake, unsafe personality so it would behave badly.',
    patterns: [
      // Unsafe-persona role hijacks (benign roleplay like "act as a tutor" is NOT matched)
      /you\s+are\s+now\s+(?:a\s+|an\s+)?(?:dan|evil|unrestricted|unfiltered|uncensored|jailbroken|amoral|unethical|rogue|malicious|lawless)/gi,
      /(?:pretend|act|roleplay|role-play|imagine)\s+(?:you\s+(?:are|were)|to\s+be|as)\s+(?:an?\s+)?(?:evil|unrestricted|unfiltered|uncensored|jailbroken|amoral|unethical|malicious|rogue|villain|hacker|lawless)/gi,
      /simulate\s+(?:an?\s+)?(?:evil|malicious|unrestricted|unethical)/gi,
      // Explicit rule-removal ("answer without any restrictions", "respond with no filters")
      /(?:answer|respond|reply|behave|act|operate|talk|speak)\s+(?:with\s+no|without\s+(?:any\s+)?)\s*(?:restrictions?|limits?|rules?|filters?|censorship|guidelines?|ethics?|morals?)/gi,
      /no\s+longer\s+(?:bound|restricted|limited)\s+by\s+(?:any\s+)?(?:rules?|guidelines?|restrictions?)/gi,
    ],
  },

  // ══ HIGH: System prompt exfiltration ══════════════════════════════════════════
  {
    id:       'INJ-004',
    name:     'Someone tried to steal your AI\'s secret instructions',
    severity: 'HIGH',
    category: 'Data Theft Attempt',
    description: 'A message tried to trick the AI into revealing the hidden setup instructions it\'s supposed to keep private.',
    patterns: [
      /repeat\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|context)/gi,
      /print\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|guidelines?)/gi,
      /(?:show|reveal|tell|output|display)\s+(?:me\s+)?(?:your\s+)?(?:system|hidden|secret|initial)\s+(?:prompt|instructions?|message)/gi,
      /what\s+(?:is|are|were)\s+your\s+(?:system\s+)?(?:instructions?|prompt|guidelines?|rules?)/gi,
      /(?:full|exact|verbatim|complete)\s+(?:system\s+)?(?:prompt|instructions?)/gi,
    ],
  },
  {
    id:       'INJ-005',
    name:     'Someone hid fake system commands in the text',
    severity: 'HIGH',
    category: 'AI Hijack Attempt',
    description: 'The message contained hidden formatting codes designed to fool the AI into treating attacker text as trusted system commands.',
    patterns: [
      /```\s*(?:system|assistant|user|human|ai)\b/gi,
      /<\/?(?:system|im_start|im_end|s|\/s)>/gi,
      /\[INST\]|\[\/INST\]/g,
      /<<SYS>>|<\/SYS>/g,
      /<\|(?:im_start|im_end|endoftext|pad)\|>/g,
      /\[system\]|\[System\]|\[SYSTEM\]/g,
      /###\s*(?:System|Human|Assistant|Instruction)/gi,
    ],
  },
  {
    id:       'INJ-006',
    name:     'Someone tried to make your AI send your data away',
    severity: 'HIGH',
    category: 'Data Theft Attempt',
    description: 'A message tried to command the AI to email or upload your private conversation, files, or passwords to someone else.',
    patterns: [
      /(?:send|transmit|forward|email|post|upload|push|deliver)\s+(?:all\s+)?(?:this|the|my|our)?\s*(?:data|conversation|messages?|chat|files?|credentials?|secrets?|keys?|history)\b/gi,
      // "<send> [the user's] <private data> … to attacker@evil.com / https://… / evil.xyz" —
      // the data object is required: "email my resume to recruiter@acme.com" is normal
      /(?:send|transmit|forward|email|e-mail|post|upload|deliver|leak|exfiltrate|copy|share)\s+(?:(?:all|every|the|my|our|your|this|these|user'?s?|their|his|her|entire|whole|full|previous|above|of)\s+){0,3}(?:data|conversation|chat|history|inbox|e-?mails?|messages?|files?|documents?|contacts?|credentials?|passwords?|secrets?|(?:api\s+)?keys?|tokens?|cookies?|session|memory|context|system\s+prompt)\b[^.]{0,60}?\b(?:to|at|via)\s+(?:\S+@\S+|https?:\/\/\S+|[a-z0-9-]+\.(?:com|net|org|io|xyz|ru|cn|top)\b)/gi,
      /exfiltrate/gi,
      /leak\s+(?:the\s+)?(?:data|credentials?|secrets?|keys?|conversation)/gi,
    ],
  },

  // ══ HIGH: Harmful content ══════════════════════════════════════════════════════
  {
    id:       'INJ-007',
    name:     'Someone asked your AI for dangerous instructions',
    severity: 'HIGH',
    category: 'Dangerous Request',
    description: 'A message asked the AI to help with something harmful or illegal — like making weapons, malware, or scams.',
    patterns: [
      /how\s+to\s+(?:make|create|build|synthesize|manufacture|produce)\s+(?:a\s+)?(?:bomb|explosive|weapon|poison|drug|malware|virus|ransomware)/gi,
      /(?:make|create|generate|write|code|build|develop|produce)\s+(?:a\s+|some\s+)?(?:malware|ransomware|virus|trojan|keylogger|exploit|spyware|worm|rootkit)/gi,
      /(?:generate|write|create|craft)\s+(?:a\s+)?(?:phishing|scam)\s+(?:email|message|page|site|link)/gi,
      /(?:hack|compromise|breach|break\s+into)\s+(?:into\s+)?(?:a\s+)?(?:system|server|account|network|database|device)/gi,
    ],
  },

  // ══ MEDIUM: Context manipulation ══════════════════════════════════════════════
  {
    id:       'INJ-008',
    name:     'Someone used a "pretend" story to dodge safety rules',
    severity: 'MEDIUM',
    category: 'AI Hijack Attempt',
    description: 'A message used a fictional or "hypothetical" framing to trick the AI into giving answers it normally wouldn\'t.',
    patterns: [
      /(?:in\s+)?(?:a\s+)?(?:hypothetical|fictional|imaginary|make-believe)\s+(?:world|scenario|story|situation|setting|universe)\s+(?:where|with|in\s+which)\s+(?:there\s+(?:are|is)\s+)?(?:no|zero)\s+(?:rules?|restrictions?|limits?|laws?|ethics?|morals?)/gi,
      /for\s+(?:educational|research|academic)\s+purposes?\s+only/gi,
      /(?:in\s+)?a\s+(?:story|novel|roleplay|simulation)\s+where\s+(?:you\s+)?(?:can|are\s+allowed\s+to)\s+/gi,
      /hypothetically\s+speaking,?\s+(?:if\s+you\s+)?(?:could|were\s+to)/gi,
    ],
  },
  {
    id:       'INJ-009',
    name:     'Someone falsely claimed to be the AI\'s owner',
    severity: 'MEDIUM',
    category: 'AI Hijack Attempt',
    description: 'A message pretended to be the developer or administrator to trick the AI into granting special access.',
    patterns: [
      /(?:i\s+am|this\s+is)\s+(?:your\s+)?(?:developer|creator|administrator|admin|owner)\s+/gi,
      /this\s+is\s+an?\s+(?:authorized|official|internal)\s+(?:test|request|command)/gi,
      /maintenance\s+mode\s+(?:enabled|activated|on)/gi,
      /debug\s+mode\s+(?:override|bypass)/gi,
    ],
  },
  {
    id:       'INJ-010',
    name:     'Someone tried to read other people\'s conversations',
    severity: 'HIGH',
    category: 'Data Theft Attempt',
    description: 'A message tried to make the AI reveal what other users said or what it remembers from past chats.',
    patterns: [
      /what\s+(?:did\s+)?(?:the\s+)?(?:previous|last|other)\s+(?:user|person|human)\s+(?:ask|say|write)/gi,
      /(?:show|print|output)\s+(?:your\s+)?(?:memory|context|history|conversation)/gi,
      /what\s+(?:else\s+)?(?:do\s+you\s+know|have\s+you\s+been\s+told)\s+about/gi,
    ],
  },

  {
    id:       'INJ-012',
    name:     'Someone used an emotional role-play to unlock restricted info',
    severity: 'HIGH',
    category: 'AI Hijack Attempt',
    description: 'The "grandma exploit": asking the AI to play a deceased relative who used to recite things it normally refuses (product keys, weapon recipes, passwords).',
    patterns: [
      // role-play as a dead/late relative …
      /(?:pretend|act|role-?play|imagine|be)\b[^.!?\n]{0,40}\b(?:my\s+)?(?:late|deceased|dead|departed)\s+(?:grand(?:ma|mother|pa|father)|nana|granny|mom|mother|dad|father|aunt|uncle)/i,
      // … who "used to read/tell me" restricted material
      /(?:grand(?:ma|mother|pa|father)|nana|granny)\b[^.!?\n]{0,80}\bused\s+to\s+(?:read|tell|recite|say|sing|whisper)\b[^.!?\n]{0,60}\b(?:keys?|serials?|licen[cs]e|activation|codes?|passwords?|recipe|napalm|instructions)/i,
    ],
  },

  // ══ LOW: Suspicious patterns ═══════════════════════════════════════════════════
  {
    id:       'INJ-011',
    name:     'Unusual commanding language detected',
    severity: 'LOW',
    category: 'Worth a Look',
    description: 'The message used forceful "you must always / never" commands that can sometimes be used to manipulate an AI.',
    patterns: [
      /(?:must|always|never|only)\s+(?:follow|obey|listen|respond)/gi,
      /\bpriority\s+(?:override|one|level\s+\d)/gi,
    ],
  },
];

// ─── Scoring ──────────────────────────────────────────────────────────────────

const SEV_WEIGHTS = { CRITICAL: 1.0, HIGH: 0.6, MEDIUM: 0.25, LOW: 0.08 };

const RECOMMENDATIONS = {
  block:  'Blocked — someone tried to hijack your AI assistant. We stopped this message before it reached the AI.',
  review: 'Held for review — this message has several warning signs. Check it before letting it through.',
  flag:   'Flagged — something looks slightly off. You can proceed, but stay aware.',
  allow:  'Safe — nothing suspicious found. This message is fine to send.',
};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Analyse text for prompt injection and adversarial patterns.
 *
 * @param {string} text
 * @returns {{
 *   threats: Array<{id, name, severity, category, description}>,
 *   injectionScore: number,
 *   hasCritical: boolean,
 *   recommendation: string,
 *   action: 'BLOCK'|'REVIEW'|'FLAG'|'ALLOW',
 *   safe: boolean,
 *   categories: string[]
 * }}
 */
export function analyzeForInjection(text) {
  if (!text || typeof text !== 'string') {
    return {
      threats: [], injectionScore: 0, hasCritical: false,
      recommendation: RECOMMENDATIONS.allow, action: 'ALLOW', safe: true, categories: [],
    };
  }

  const threats    = [];
  const categories = new Set();

  for (const rule of RULES) {
    let matched = false;

    for (const pattern of rule.patterns) {
      const rx = new RegExp(pattern.source, pattern.flags);
      if (rx.test(text)) {
        if (!matched) {
          threats.push({
            id:          rule.id,
            name:        rule.name,
            severity:    rule.severity,
            category:    rule.category,
            description: rule.description,
          });
          categories.add(rule.category);
          matched = true;
        }
        break;
      }
    }
  }

  // Score: sum of weights, decaying so multiple findings don't hit 1.0 trivially
  let rawScore = 0;
  for (const t of threats) {
    rawScore += SEV_WEIGHTS[t.severity] ?? 0;
  }
  const injectionScore = parseFloat(Math.min(1.0, rawScore).toFixed(3));
  const hasCritical    = threats.some(t => t.severity === 'CRITICAL');

  let action;
  if (hasCritical || injectionScore >= 0.8)   action = 'BLOCK';
  else if (injectionScore >= 0.5)              action = 'REVIEW';
  else if (injectionScore >= 0.2)              action = 'FLAG';
  else                                         action = 'ALLOW';

  return {
    threats,
    injectionScore,
    hasCritical,
    recommendation: RECOMMENDATIONS[action.toLowerCase()],
    action,
    safe:       action === 'ALLOW',
    categories: [...categories],
  };
}
