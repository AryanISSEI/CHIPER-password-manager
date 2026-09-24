import math
import re
import string

def calculate_password_strength(password: str) -> dict:
    """Calculates password strength using entropy and pattern detection.

    Returns a dict with:
        score:    0–100 integer
        label:    "Weak" | "Fair" | "Good" | "Strong" | "Very Strong"
        entropy:  float (bits of entropy)
        issues:   list of string warnings
    """
    issues = []

    # ── Character set size ────────────────────────────────────────────
    charset_size = 0
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^a-zA-Z0-9]', password))

    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32

    if charset_size == 0:
        charset_size = 1

    # ── Entropy ───────────────────────────────────────────────────────
    entropy = len(password) * math.log2(charset_size) if charset_size > 1 else 0

    # ── Pattern detection ─────────────────────────────────────────────
    if len(password) < 8:
        issues.append("Too short (less than 8 characters)")
    elif len(password) < 12:
        issues.append("Short (less than 12 characters)")

    if not has_upper:
        issues.append("No uppercase letters")
    if not has_lower:
        issues.append("No lowercase letters")
    if not has_digit:
        issues.append("No numbers")
    if not has_symbol:
        issues.append("No special characters")

    # Common patterns
    common_patterns = [
        r'12345', r'password', r'qwerty', r'abc123',
        r'letmein', r'admin', r'welcome', r'monkey',
        r'111111', r'000000',
    ]
    lower_pw = password.lower()
    for pattern in common_patterns:
        if pattern in lower_pw:
            issues.append(f"Contains common pattern: '{pattern}'")
            entropy *= 0.5  # Penalize
            break

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters")
        entropy *= 0.8

    # ── Score mapping ─────────────────────────────────────────────────
    if entropy < 28:
        score, label = min(int(entropy / 28 * 25), 24), "Weak"
    elif entropy < 36:
        score, label = 25 + int((entropy - 28) / 8 * 25), "Fair"
    elif entropy < 60:
        score, label = 50 + int((entropy - 36) / 24 * 25), "Good"
    elif entropy < 80:
        score, label = 75 + int((entropy - 60) / 20 * 15), "Strong"
    else:
        score, label = min(90 + int((entropy - 80) / 40 * 10), 100), "Very Strong"

    return {
        'score': score,
        'label': label,
        'entropy': round(entropy, 1),
        'issues': issues,
    }


# ── Passphrase Generator ─────────────────────────────────────────────

# Curated word list — common English words, 4-8 chars, easy to type
_WORDLIST = [
    "about", "above", "acid", "across", "after", "again", "agree", "album",
    "alert", "alive", "allow", "alone", "alpha", "alter", "among", "angel",
    "anger", "angle", "ankle", "apart", "apple", "april", "arena", "armor",
    "arrow", "aside", "atlas", "avoid", "badge", "baker", "beach", "beard",
    "beast", "begin", "below", "bench", "berry", "birth", "blade", "blame",
    "blank", "blast", "blaze", "blend", "blind", "block", "bloom", "board",
    "bonus", "boost", "brain", "brave", "bread", "break", "brick", "brief",
    "bring", "broad", "brook", "brush", "build", "burst", "cable", "camel",
    "cargo", "carry", "catch", "cedar", "chain", "chair", "chalk", "chaos",
    "charm", "chase", "cheap", "chess", "chief", "child", "chill", "chunk",
    "civic", "claim", "clash", "class", "clean", "clear", "click", "cliff",
    "climb", "clock", "clone", "close", "cloud", "coach", "coast", "coral",
    "count", "court", "cover", "craft", "crane", "crash", "crazy", "cream",
    "creek", "crest", "crisp", "cross", "crowd", "crush", "curve", "cycle",
    "dance", "death", "debug", "decay", "delta", "demon", "depth", "derby",
    "devil", "digit", "disco", "ditto", "donor", "doubt", "draft", "drain",
    "drama", "drawn", "dream", "drift", "drink", "drive", "drone", "drops",
    "drunk", "dwarf", "eager", "eagle", "earth", "eight", "elbow", "elder",
    "ember", "empty", "enemy", "enjoy", "enter", "entry", "equal", "error",
    "essay", "ethic", "event", "every", "exact", "exile", "exist", "extra",
    "fable", "facet", "faith", "fancy", "fault", "feast", "fence", "fiber",
    "field", "fight", "final", "flame", "flask", "flesh", "float", "flood",
    "floor", "fluid", "flush", "focus", "force", "forge", "forum", "found",
    "frame", "fraud", "fresh", "front", "frost", "fruit", "gamma", "ghost",
    "giant", "given", "glass", "gleam", "globe", "gloom", "glory", "grace",
    "grade", "grain", "grand", "grant", "graph", "grasp", "grass", "grave",
    "greed", "green", "greet", "grief", "grill", "grind", "groan", "gross",
    "grove", "growl", "grown", "guard", "guest", "guide", "guilt", "habit",
    "happy", "hardy", "harsh", "haven", "hazel", "heart", "heavy", "hedge",
    "hello", "honor", "horse", "hotel", "house", "human", "humor", "ideal",
    "image", "inbox", "index", "indie", "inner", "input", "ivory", "jewel",
    "joker", "jolly", "judge", "juice", "knack", "kneel", "knife", "knobs",
    "knock", "known", "label", "lance", "large", "laser", "latch", "later",
    "laugh", "layer", "learn", "leave", "legal", "lemon", "level", "lever",
    "light", "linen", "liver", "llama", "local", "lodge", "logic", "loose",
    "lotus", "lover", "lucky", "lunar", "lunch", "magic", "manor", "maple",
    "march", "mason", "match", "maybe", "mayor", "medal", "media", "mercy",
    "merit", "metal", "micro", "might", "minor", "minus", "misty", "model",
    "money", "month", "moral", "motor", "mount", "mouse", "movie", "music",
    "naive", "nerve", "never", "night", "noble", "noise", "north", "noted",
    "novel", "nurse", "nylon", "ocean", "olive", "omega", "onion", "opera",
    "orbit", "order", "outer", "ozone", "panda", "panel", "panic", "party",
    "patch", "pause", "peace", "pearl", "penny", "phase", "phone", "photo",
    "piano", "piece", "pilot", "pixel", "pizza", "place", "plain", "plane",
    "plant", "plate", "plaza", "plumb", "plume", "plush", "point", "poker",
    "polar", "pound", "power", "press", "price", "pride", "prime", "print",
    "prior", "prize", "proof", "prose", "proud", "prove", "proxy", "pulse",
    "punch", "pupil", "purse", "queen", "quest", "quick", "quiet", "quota",
    "radar", "radio", "rally", "ranch", "range", "rapid", "ratio", "reach",
    "ready", "realm", "rebel", "reign", "relax", "renew", "rider", "ridge",
    "right", "risky", "rival", "river", "robin", "robot", "rocky", "roman",
    "round", "route", "royal", "rugby", "ruler", "rumor", "rural", "saint",
    "salad", "salon", "sauce", "scale", "scene", "scope", "scout", "sense",
    "serve", "seven", "shade", "shake", "shall", "shame", "shape", "share",
    "shark", "sharp", "sheep", "sheet", "shelf", "shell", "shift", "shirt",
    "shock", "shore", "short", "shout", "sight", "sigma", "silly", "since",
    "sixth", "sixty", "skate", "skill", "skull", "slang", "slash", "slate",
    "sleep", "slice", "slide", "slope", "smart", "smell", "smile", "smoke",
    "snake", "solar", "solid", "solve", "sonic", "sorry", "sound", "south",
    "space", "spare", "spark", "speak", "speed", "spend", "spice", "spine",
    "spoke", "spoon", "sport", "spray", "squad", "stack", "staff", "stage",
    "stake", "stale", "stamp", "stand", "stark", "start", "state", "stead",
    "steal", "steam", "steel", "steep", "steer", "stern", "stick", "still",
    "stock", "stone", "stood", "store", "storm", "story", "stove", "straw",
    "strip", "stuck", "study", "stuff", "style", "sugar", "suite", "sunny",
    "super", "surge", "swamp", "swear", "sweep", "sweet", "swift", "swing",
    "sword", "syrup", "table", "taste", "tempo", "theft", "thick", "thing",
    "think", "those", "three", "throw", "thumb", "tiger", "tight", "timer",
    "tired", "title", "toast", "token", "torch", "total", "touch", "tough",
    "tower", "toxic", "trace", "track", "trade", "trail", "train", "trait",
    "treat", "trend", "trial", "tribe", "trick", "troop", "truck", "truly",
    "trump", "trunk", "trust", "truth", "tulip", "tumor", "tuner", "twice",
    "twist", "ultra", "uncle", "under", "union", "unite", "unity", "until",
    "upper", "urban", "usage", "usual", "valid", "value", "vapor", "vault",
    "venue", "verse", "vigor", "vinyl", "viral", "virus", "visit", "vivid",
    "vocal", "voice", "voter", "wagon", "waste", "watch", "water", "weave",
    "wheel", "where", "which", "while", "white", "whole", "width", "witch",
    "woman", "world", "worth", "wound", "wrath", "write", "wrong", "yacht",
    "yield", "young", "youth", "zebra",
]


def generate_passphrase(
    word_count: int = 5,
    separator: str = "-",
    capitalize: bool = False,
) -> str:
    """Generate a passphrase from random dictionary words.

    Default: 5 words separated by hyphens (e.g., "castle-dream-solar-brave-kneel").
    With a ~500-word list, 5 words ≈ 45 bits of entropy (comparable to a
    13-char random password with mixed case + digits).

    Args:
        word_count:  Number of words (3–10).
        separator:   Character between words ("-", " ", ".", "_").
        capitalize:  If True, capitalize each word.

    Returns:
        A passphrase string.
    """
    import secrets as _secrets

    word_count = max(3, min(word_count, 10))
    words = [_secrets.choice(_WORDLIST) for _ in range(word_count)]

    if capitalize:
        words = [w.capitalize() for w in words]

    return separator.join(words)
