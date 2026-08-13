"""
PII Redaction Engine
=====================
Detects and redacts PII from free text, replacing each unique piece of PII
with a consistent fake alternative (same input -> same fake output, every time
it appears in the document).

Detection strategy (hybrid, see README.md for rationale):
  - Structured / high-precision PII (email, phone, SSN, credit card, IP,
    date of birth) -> regex + light validation (e.g. Luhn check for cards).
  - Unstructured PII (full names, company names, addresses) -> spaCy NER
    (en_core_web_sm) for PERSON / ORG / GPE, combined with regex heuristics
    for street-address blocks (PIN/ZIP-anchored).

Usage:
    from redactor import PiiRedactor
    r = PiiRedactor()
    redacted_text, spans = r.redact(text)
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import List, Tuple, Dict

import spacy
from faker import Faker

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PiiSpan:
    start: int
    end: int
    text: str
    label: str  # e.g. EMAIL, PHONE, PERSON, COMPANY, ADDRESS, SSN, CREDIT_CARD, DOB, IP


# ---------------------------------------------------------------------------
# Regex patterns for structured PII
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# Indian + generic international phone numbers. Ordered so the most specific
# (with country code) patterns are tried first to avoid partial matches.
# Country code allows an optional space after '+' (e.g. "+ 91 98765 43210",
# which appears in the source document) as well as the more common "+91".
PHONE_RE = re.compile(
    r"(?<!\d)("
    r"\+\s?91[-\s]?\d{2,5}[-\s]?\d{2,5}[-\s]?\d{2,6}"     # +91 20 2561 2345 / + 91 20 2561 2345
    r"|\+\s?91[-\s]?\d{5}[-\s]?\d{5}"                      # +91 98765 43210 / + 91 98765 43210
    r"|\+\s?1[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{4}"           # +1 555 123 4567
    r"|\b0\d{2,4}[-\s]\d{6,8}\b"                          # 020-26234500 (STD code)
    r"|\b\d{5}[-\s]\d{5}\b"                                # 98765 43210
    r"|\b\d{3}[-\s]\d{3}[-\s]\d{4}\b"                     # 555-123-4567
    r")(?!\d)"
)

SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# 13-19 digits in groups of 4 (with optional spaces/dashes), or contiguous.
CREDIT_CARD_RE = re.compile(
    r"\b(?:\d[ -]?){13,19}\b"
)

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# Date-of-birth: a date token located near a DOB-indicating keyword on the
# same line/short window. Matches numeric (DD/MM/YYYY, DD-MM-YYYY) and
# written-out (Month DD, YYYY) forms.
DOB_CONTEXT_RE = re.compile(r"\b(date of birth|born on|d\.?o\.?b\.?)\b", re.I)
DATE_RE = re.compile(
    r"\b(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}"
    r"|(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December)\s+\d{1,2},?\s+\d{4})\b"
)

# Street-address heuristic: a chunk containing a 5/6-digit postal (PIN/ZIP)
# code preceded by street/city-style words within ~120 chars.
ADDRESS_PIN_RE = re.compile(r"\b\d{3}\s?\d{3}\b|\b\d{5}(-\d{4})?\b")
ADDRESS_KEYWORDS = re.compile(
    r"\b(road|street|st\.|marg|lane|avenue|ave\.|block|sector|floor|tower|"
    r"village|taluka|nagar|colony|apartment|flat|plot|survey|society|"
    r"housing|residency|compound|chowk|gaon|chs\b)\b", re.I
)

# Recurring capitalised legal/regulatory defined-terms that spaCy's PERSON/ORG
# labels mis-tag as names/companies in offering-document prose (e.g. "the
# Equity Shares", "Bid/Offer Closing Day"). Built from error analysis during
# evaluation (see eval/README) -- a concrete example of the "add a stoplist
# entry" extension path described in README.md.
DEFINED_TERM_STOPLIST = {
    "offer", "equity shares", "the equity shares", "prospectus",
    "the designated stock exchange", "registrar", "bidders", "bids",
    "allotment", "floor price", "cap price", "schedule xiii",
    "bid/offer closing day", "the bid cum application form",
    "corporate office", "key managerial personnel",
    "long term bank facilities", "the care report", "statutory auditors",
    "esop", "bcd", "pli", "quick service restaurants", "sek", "krona",
    "inter alia", "ncl", "upi id", "upi bidders", "anchor investors",
    "asba", "the promoter selling shareholders", "promoter selling",
    "the self certified syndicate banks", "aadhaar",
    # Document title / running-header text -- confirmed false positive:
    # spaCy tags "RED HERRING PROSPECTUS" as ORG because of the all-caps
    # legal-document style. It is not a company.
    "red herring prospectus", "draft red herring prospectus",
    "letter of offer", "abridged prospectus", "general information document",
    "board", "the board", "board of directors", "risks", "risk factors",
    "email", "size", "eligibility", "our company", "the company",
    "management", "our promoters", "promoter and promoter group",
    "bid amount", "refund bank", "the refund bank", "escrow bank",
    "sponsor bank", "banker(s) to the offer", "bankers to the offer",
    # Generic roles/terms from QA audit:
    "depository participant", "depository participants", "collecting depository participants",
    "designated depository participant", "designated depository participants",
    "depository", "participants", "bidder's dp id", "bidder dp id", "dp id",
    "key managerial personnel", "key managerial", "selling shareholders", "selling shareholder",
    "brlms", "brlm", "lead managers", "lead manager", "book running lead manager",
    "book running lead managers", "syndicate member", "syndicate members",
    "self certified syndicate bank", "self certified syndicate banks",
    "scsb", "scsbs", "newspaper", "daily newspaper", "marathi daily newspaper",
    "widely circulated marathi daily newspaper", "english daily newspaper",
    "widely circulated english daily newspaper", "daily", "newspapers",
    "corrigenda thereto", "corrigendum", "corrigenda", "public announcement",
    "pre-filed draft red herring prospectus",
}

# Regex for URL/domain name (redacts all URLs and domains, supporting multi-level domains)
URL_RE = re.compile(
    r"\b(?:https?://)?(?:www\.)?((?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})(?:/[a-zA-Z0-9\-_./%?=&]*)?\b",
    re.I
)

# Legal-entity suffixes used to anchor high-precision company-name detection.
# A capitalised phrase ending in one of these is a strong company signal
# regardless of what spaCy's ORG label says; conversely, an ORG entity
# *without* one of these is usually a defined term / regulator / generic
# noun phrase, not a company that needs redacting (see README "Company
# detection precision").
COMPANY_SUFFIXES = (
    r"Limited|Ltd\.?|Private Limited|Pvt\.?\s?Ltd\.?|LLP|LLC|Inc\.?|"
    r"Corporation|Corp\.?|Co\.?|Family Trust|Private"
)
# NOTE: bare "Bank"/"Trust"/"Co." style suffixes were deliberately left out
# here. This document uses "Bank" as part of many generic defined terms
# ("Refund Bank", "Escrow Bank", "Sponsor Bank", "Banker(s) to the Offer")
# that are NOT specific company names -- adding "Bank" as a suffix anchor
# caused exactly that false-positive pattern in testing. The tradeoff: an
# actual bank referenced only as e.g. "HDFC Bank" (no "Limited") would be
# missed. Documented in README as a known false-negative.
# (?i:...) scopes case-insensitivity to just the suffix, so the document
# (which uses the suffix in both "Private Limited" and ALL-CAPS "PRIVATE
# LIMITED" headers/title blocks) matches either way, while the capitalised-
# word-run portion of the name still requires a leading capital letter per
# token (so it doesn't start matching mid-sentence on lowercase prose).
# Matches runs of capitalized words/numbers/lowercase coordinators ending in a company suffix.
COMPANY_SUFFIX_RE = re.compile(
    r"\b((?:(?:[A-Z0-9&][A-Za-z0-9&.\'’\-]*|and|of|for|in|to|at|on|&)\s+){1,}"
    r"(?i:Private\s+Limited|Pvt\.?\s?Ltd\.?|Family\s+Trust|"
    r"Limited|Ltd\.?|LLP|LLC|Inc\.?|Corporation|Corp\.?|Private))\b"
)


# Generic lead-in words that can get swept into the start of a
# COMPANY_SUFFIX_RE match because they're capitalised and directly precede
# the real company name (e.g. "Registered Office of our Company KSH
# International Limited" -> the regex's leftmost-match behaviour would
# otherwise capture "Company KSH International Limited"). Stripped from the
# front of a match in _clean_company_match below rather than tightened in
# the regex itself, since a lookbehind approach breaks on the many ways
# these lead-ins combine.
COMPANY_GENERIC_LEAD_WORDS = {
    "company", "corporate", "registered", "office", "the", "our", "of", "a", "an", "formerly", "collectively",
}


def _valid_company_match(text: str) -> bool:
    """Require at least two name tokens before normal legal suffixes.

    This prevents fragments such as "India Limited", "Private Limited",
    "Advisory Private Limited" and "Pandit, LLP" from being treated as
    standalone companies. Family Trust is intentionally allowed with one
    name token (e.g. "Makalu Family Trust").
    """
    t = text.strip()
    family = re.search(r"\s+(?i:Family\s+Trust)\s*$", t)
    if family:
        prefix = t[:family.start()].strip()
        return len(prefix.split()) >= 1
    suffix = re.search(
        r"\s+(?i:Private\s+Limited|Pvt\.?\s?Ltd\.?|Limited|Ltd\.?|LLP|LLC|Inc\.?|Corporation|Corp\.?|Private)\s*$",
        t,
    )
    if not suffix:
        return False
    prefix = t[:suffix.start()].strip()
    return len(prefix.split()) >= 2



def _clean_company_match(text: str) -> str:
    words = text.split()
    while len(words) > 1 and words[0].lower() in COMPANY_GENERIC_LEAD_WORDS:
        words.pop(0)
    return " ".join(words)

# Contextual person-name rules: a full name following one of these
# document-role labels is redacted even if spaCy's PERSON model misses it
# (e.g. "Contact Person: Tushar Wakhele" -- a single, isolated name that
# NER has no surrounding sentence context to classify). Deliberately
# anchored to explicit role labels rather than "any capitalised phrase" to
# avoid trading recall for precision.
PERSON_CONTEXT_RE = re.compile(
    r"\b(?:Contact Person|Promoters?|Individual Promoters?|Director|"
    r"Chairman|Managing Director|Company Secretary|Compliance Officer|"
    r"Chief Financial Officer|Whole[- ]time Director)\s*:?\s*"
    r"((?:[A-Z][a-zA-Z'\-]+(?:\s+|,\s*|\s+and\s+))+[A-Z][a-zA-Z'\-]+)",
)

# Legal-document prose often contains a person's name followed by a field
# label or role, e.g. "Tushar Wakhele Website" or "Sarthak Malvadkar,
# Company Secretary and Compliance Officer".  spaCy can absorb the label into
# the PERSON span.  Trim only these explicit suffixes; do not use a generic
# capitalisation rule.
PERSON_ROLE_SUFFIX_RE = re.compile(
    r"\s+(?:Company Secretary|Compliance Officer|SEBI Registration No(?:\.|\b)|"
    r"Website|Email|Telephone|Phone|Contact Person|Registration No)\b.*$",
    re.I,
)

# Contexts in this prospectus where a capitalised phrase is demonstrably a
# document term rather than a person's name.  These are precision safeguards
# derived from observed false positives; adding a new PII type remains a
# separate detector rather than broadening this list.
PERSON_FALSE_POSITIVE_STOPLIST = {
    "selling shareholder", "selling shareholders", "offer price",
    "mutual funds", "key managerial", "acknowledgement slip",
    "share transfer agents", "individual bidders", "qib bidders",
    "wilful defaulter", "identification number", "dp/ depository participant",
    "nro account", "circuit kilometers", "air conditioning",
    "mega volt-amperes", "photo voltaic", "pat cagr", "pat margin",
    "c. operational", "b. non-gaap measures", "reference rate",
    "promoter trusts", "parents branch", "rajesh branch", "sangeeta branch",
    "supa facility", "bandra kurla complex", "bandra east",
    "bandra east mumbai", "deccan gymkhana", "gopal bo",
    "iso 9001:2015", "iso 14001:2015", "iso 45001:2018",
    "tanishq showroom", "tara chambers", "listing sebi bhavan",
    "marg backbay reclamation churchgate", "sancheti hospital shivajinagar",
    "kubera chambers opp", "group and promoter selling shareholders",
    "group, promoter selling shareholders and shareholders",
    "group and promoter selling shareholders and shareholders",
    "kmp/ key managerial personnel", "gram jyoti",
    # Generic roles/terms from QA audit:
    "depository participant", "depository participants", "collecting depository participants",
    "designated depository participant", "designated depository participants",
    "depository", "participants", "bidder's dp id", "bidder dp id", "dp id",
    "key managerial personnel", "key managerial", "selling shareholders", "selling shareholder",
    "brlms", "brlm", "lead managers", "lead manager", "book running lead manager",
    "book running lead managers", "syndicate member", "syndicate members",
    "self certified syndicate bank", "self certified syndicate banks",
    "scsb", "scsbs", "newspaper", "daily newspaper", "marathi daily newspaper",
    "widely circulated marathi daily newspaper", "english daily newspaper",
    "widely circulated english daily newspaper", "daily", "newspapers",
    "corrigenda thereto", "corrigendum", "corrigenda", "public announcement",
    "pre-filed draft red herring prospectus", "draft red herring prospectus",
    "red herring prospectus", "prospectus", "board", "the board",
    "board of directors", "risks", "risk factors", "bidder’s dp id", "bidder's dp id"
}

# A legal-style phrase that explicitly introduces a named expert/engineer.
# This catches names that spaCy can miss because they occur only once.
LEGAL_PERSON_CONTEXT_RE = re.compile(
    r"\b(?:from|namely,|appointed by [^,;]{0,100},\s*namely,)\s*"
    r"((?:[A-Z][a-zA-Z'\-]+\s+){1,3}[A-Z][a-zA-Z'\-]+)"
    r"(?=\s*(?:,|;|\bbearing\b|\bto\b|\bfor\b|$))",
)

# Explicit contact-person field parser.  Unlike generic NER, this is a
# high-signal source of names in this prospectus and handles slash-separated
# lists such as "Eric Bacha/ Sachin Gawade/ Pravin Teli".
CONTACT_PERSON_FIELD_RE = re.compile(
    r"\bContact Person\s*:\s*([^;]+?)(?=;|\bTelephone\b|\bPhone\b|\bWebsite\b|\bEmail\b|$)",
    re.I,
)

# Well-known regulators / exchanges / statutes that are NOT sensitive
# "company PII" even though spaCy tags them ORG. Explicit precision choice,
# see README.
ORG_WHITELIST = {
    "sebi", "rbi", "nse", "bse", "cdsl", "nsdl", "icai", "roc",
    "companies act", "sebi icdr regulations", "income tax act",
    "reserve bank of india", "securities and exchange board of india",
    "registrar of companies", "gst", "fema", "irdai",
}

# Short all-caps acronyms that spaCy's ORG label frequently mis-tags in
# financial/legal documents (regulatory / form-field jargon, not companies).
# Documented false-positive mitigation, see README "Known false positives".
ORG_ACRONYM_STOPLIST = {
    "ssn", "pan", "gst", "tan", "kyc", "ifsc", "rtgs", "neft", "isin",
    "cin", "din", "nav", "ipo", "faq", "sic", "usd", "inr", "gaap", "ind as",
    "ip", "dob",
}


def _extract_contact_names(field: str) -> List[str]:
    """Extract individual names from a Contact Person field."""
    field = PERSON_ROLE_SUFFIX_RE.sub("", field).strip(" ,")
    names = []
    for part in re.split(r"/|\band\b", field, flags=re.I):
        part = PERSON_ROLE_SUFFIX_RE.sub("", part).strip(" ,")
        # A comma in this field normally separates a name from its role;
        # keep only the first clause.
        part = part.split(",", 1)[0].strip()
        words = part.split()
        if 2 <= len(words) <= 5 and all(re.fullmatch(r"[A-Z][A-Za-z'\-.]*", w) for w in words):
            norm_part = re.sub(r"\s+", " ", part.lower())
            if norm_part not in PERSON_FALSE_POSITIVE_STOPLIST:
                names.append(part)
    return names


def luhn_ok(digits: str) -> bool:
    """Luhn checksum, used to cut false positives on the credit-card regex
    (plain digit runs of 13-19 digits are common in ID/CIN/ISIN numbers in
    financial documents and are NOT credit cards)."""
    d = [int(c) for c in digits]
    checksum = 0
    parity = len(d) % 2
    for i, digit in enumerate(d):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


# ---------------------------------------------------------------------------
# Fake-value generator (consistent original -> fake mapping)
# ---------------------------------------------------------------------------

class FakeValueFactory:
    def __init__(self, seed: int = 42):
        self.fake = Faker()
        Faker.seed(seed)
        self._map: Dict[Tuple[str, str], str] = {}

    def _key(self, label: str, original: str) -> Tuple[str, str]:
        return (label, original.strip().lower())

    def get(self, label: str, original: str) -> str:
        # Cross-label consistency check: reuse fake if normalized string is already mapped
        norm_orig = original.strip().lower()
        for (l, o), val in self._map.items():
            if o == norm_orig:
                return val

        key = self._key(label, original)
        if key in self._map:
            return self._map[key]
        value = self._generate(label, original)
        self._map[key] = value
        return value


    def _generate(self, label: str, original: str) -> str:
        # deterministic per-value seed so re-runs are reproducible
        h = int(hashlib.sha256(original.encode()).hexdigest(), 16) % (2**32)
        local_fake = Faker()
        local_fake.seed_instance(h)

        if label == "PERSON":
            return local_fake.name()
        if label == "EMAIL":
            return local_fake.user_name().replace(".", "") + "@example.com"
        if label == "PHONE":
            digits = re.sub(r"\D", "", original)
            if original.strip().startswith("+91") or len(digits) >= 10:
                return "+91 " + str(local_fake.random_number(digits=10, fix_len=True))
            return local_fake.phone_number()
        if label == "COMPANY":
            return local_fake.company()
        if label == "ADDRESS":
            return local_fake.address().replace("\n", ", ")
        if label == "SSN":
            return f"{local_fake.random_int(100,999)}-{local_fake.random_int(10,99)}-{local_fake.random_int(1000,9999)}"
        if label == "CREDIT_CARD":
            return local_fake.credit_card_number(card_type="visa")
        if label == "DOB":
            return local_fake.date(pattern="%d-%m-%Y")
        if label == "IP":
            return local_fake.ipv4_public()
        if label == "URL":
            return "https://example.com"
        return "[REDACTED]"


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class PiiRedactor:
    def __init__(self, seed: int = 42, use_ner: bool = True):
        self.factory = FakeValueFactory(seed=seed)
        self.use_ner = use_ner
        self.nlp = spacy.load("en_core_web_sm") if use_ner else None
        # Registry of confirmed PERSON / COMPANY strings, built by a first
        # pass over the WHOLE document (see build_registry / register_text).
        # Per-paragraph NER makes an independent, context-dependent decision
        # each time it sees a name -- it does not "remember" that it already
        # confirmed "Kushal Subbayya Hegde" is a person three paragraphs
        # earlier, so the same name can be caught in one sentence and missed
        # in the next. The registry fixes that: once a name/company is
        # confirmed anywhere in the document, every exact occurrence of it
        # everywhere else is redacted too, regardless of local NER context.
        self.person_registry: set = set()
        self.company_registry: set = set()

    def register_text(self, text: str) -> None:
        """Pass 1: scan text and add any confirmed PERSON/COMPANY entities
        to the registry. Does not modify text."""
        for s in self._find_ner(text):
            if s.label == "PERSON":
                # If a detected PERSON has a company suffix, register it as COMPANY instead
                if COMPANY_SUFFIX_RE.search(s.text) and _valid_company_match(s.text):
                    self.company_registry.add(s.text.strip())
                else:
                    self.person_registry.add(s.text.strip())
            elif s.label == "COMPANY":
                self.company_registry.add(s.text.strip())
        
        # Ensure registries are strictly disjoint (COMPANY wins)
        self.person_registry -= self.company_registry

    def _registry_spans(self, text: str) -> List[PiiSpan]:
        """Exact-match spans for every registered PERSON/COMPANY string,
        longest-first so e.g. 'Kushal Subbayya Hegde' is matched whole
        rather than only its substring 'Kushal'."""
        spans = []
        entries = (
            [(n, "PERSON") for n in self.person_registry]
            + [(n, "COMPANY") for n in self.company_registry]
        )
        entries.sort(key=lambda t: -len(t[0]))
        for name, label in entries:
            if not name.strip():
                continue
            # Allow optional plural ('s' or possessive ''s') to avoid leaving trailing plural characters
            pattern = re.compile(r"\b" + re.escape(name) + r"(?:'s|s)?\b")
            for m in pattern.finditer(text):
                spans.append(PiiSpan(m.start(), m.end(), m.group(), label))
        return spans

    # -- detection -----------------------------------------------------

    def _find_structured(self, text: str) -> List[PiiSpan]:
        spans: List[PiiSpan] = []

        for m in EMAIL_RE.finditer(text):
            spans.append(PiiSpan(m.start(), m.end(), m.group(), "EMAIL"))

        for m in SSN_RE.finditer(text):
            spans.append(PiiSpan(m.start(), m.end(), m.group(), "SSN"))

        for m in IP_RE.finditer(text):
            spans.append(PiiSpan(m.start(), m.end(), m.group(), "IP"))

        for m in CREDIT_CARD_RE.finditer(text):
            digits = re.sub(r"[ \-]", "", m.group())
            if 13 <= len(digits) <= 19 and luhn_ok(digits):
                spans.append(PiiSpan(m.start(), m.end(), m.group(), "CREDIT_CARD"))

        for m in PHONE_RE.finditer(text):
            spans.append(PiiSpan(m.start(), m.end(), m.group(), "PHONE"))

        for m in DOB_CONTEXT_RE.finditer(text):
            window_start = m.end()
            window = text[window_start:window_start + 40]
            dm = DATE_RE.search(window)
            if dm:
                s = window_start + dm.start()
                e = window_start + dm.end()
                spans.append(PiiSpan(s, e, text[s:e], "DOB"))

        for m in URL_RE.finditer(text):
            spans.append(PiiSpan(m.start(), m.end(), m.group(), "URL"))

        return spans

    def _find_address(self, text: str) -> List[PiiSpan]:
        """Heuristic: a line containing a PIN/ZIP code AND an address
        keyword is treated as an address block (the whole line is redacted
        as one ADDRESS span)."""
        spans = []
        for line_match in re.finditer(r".+", text):
            line = line_match.group()
            if ADDRESS_PIN_RE.search(line) and ADDRESS_KEYWORDS.search(line):
                s, e = line_match.start(), line_match.end()
                spans.append(PiiSpan(s, e, line, "ADDRESS"))
        return spans

    def _find_ner(self, text: str) -> List[PiiSpan]:
        """spaCy-based detection. PERSON is taken largely as-is (defined-term
        stoplist still applies). COMPANY is intentionally NOT "every spaCy
        ORG": an ORG entity is only kept if it also carries a legal-entity
        suffix (Limited, LLP, Pvt Ltd, ...). Without that constraint, spaCy
        tags generic capitalised legal/financial phrases -- "EQUITY SHARES",
        "RED HERRING PROSPECTUS", "RISK FACTORS" -- as organizations, and a
        blind ORG->COMPANY mapping ends up replacing ordinary document text
        (confirmed false positives from evaluation; see README "Company
        detection precision"). Requiring a legal suffix trades a bit of
        recall (an org referenced only by an unsuffixed short name) for a
        large precision gain, and is backstopped by COMPANY_SUFFIX_RE regex
        matches for suffixed names spaCy's ORG model misses entirely.
        """
        spans = []
        if not self.nlp:
            return spans
        # spaCy has a max doc length; chunk very long text defensively.
        CHUNK = 90000
        offset = 0
        while offset < len(text):
            chunk = text[offset:offset + CHUNK]
            doc = self.nlp(chunk)
            for ent in doc.ents:
                norm = re.sub(r"\s+", " ", ent.text.strip().lower())
                if norm in DEFINED_TERM_STOPLIST:
                    continue
                if ent.label_ == "PERSON":
                    raw = ent.text.strip()
                    # Split slash-separated names instead of turning two
                    # contact people into one synthetic person.
                    candidates = [raw]
                    if "/" in raw:
                        candidates = [x.strip() for x in raw.split("/") if x.strip()]
                    for candidate in candidates:
                        # Remove explicit field/role suffixes that spaCy can
                        # absorb into the PERSON span.
                        candidate = PERSON_ROLE_SUFFIX_RE.sub("", candidate).strip(" ,")
                        norm_candidate = re.sub(r"\s+", " ", candidate.lower())
                        if norm_candidate in PERSON_FALSE_POSITIVE_STOPLIST:
                            continue
                        words = candidate.split()
                        if len(words) < 2:
                            continue  # single-token PERSON hits are usually false positives
                        if any(w.lower() in {"a", "an", "the", "of", "in", "at", "on", "to", "for"} for w in words):
                            continue
                        # If the original entity was split/truncated, locate the
                        # candidate inside the spaCy span rather than reusing the
                        # full entity boundaries.
                        rel = raw.find(candidate)
                        if rel < 0:
                            continue
                        spans.append(PiiSpan(
                            offset + ent.start_char + rel,
                            offset + ent.start_char + rel + len(candidate),
                            candidate,
                            "PERSON",
                        ))
                elif ent.label_ == "ORG":
                    is_short_acronym = len(ent.text.strip()) <= 5 and ent.text.strip().isupper()
                    if norm in ORG_WHITELIST:
                        continue
                    if is_short_acronym and norm in ORG_ACRONYM_STOPLIST:
                        continue
                    if not COMPANY_SUFFIX_RE.search(ent.text) or not _valid_company_match(ent.text):
                        continue  # no sufficiently specific legal company name
                    spans.append(PiiSpan(offset + ent.start_char, offset + ent.end_char, ent.text, "COMPANY"))
            offset += CHUNK

        # Regex backstop: legal-suffix company names spaCy's ORG model missed
        # entirely (still gated by the same stoplist).
        for m in COMPANY_SUFFIX_RE.finditer(text):
            raw = m.group(1)
            cleaned = _clean_company_match(raw)
            if not cleaned or not _valid_company_match(cleaned):
                continue
            norm = re.sub(r"\s+", " ", cleaned.strip().lower())
            if norm in DEFINED_TERM_STOPLIST:
                continue
            # cleaned is raw with only leading generic words stripped, so
            # locate it within the matched raw span to get the real offset.
            offset_in_raw = raw.rfind(cleaned)
            s = m.start(1) + offset_in_raw
            e = s + len(cleaned)
            spans.append(PiiSpan(s, e, text[s:e], "COMPANY"))

        # Contextual person names spaCy's PERSON model misses because the
        # name appears in isolation (label + colon + name, no sentence
        # context), e.g. "Contact Person: Tushar Wakhele".
        for m in PERSON_CONTEXT_RE.finditer(text):
            name = PERSON_ROLE_SUFFIX_RE.sub("", m.group(1)).strip().rstrip(",")
            if not name:
                continue
            norm_name = re.sub(r"\s+", " ", name.lower())
            if norm_name in DEFINED_TERM_STOPLIST or norm_name in PERSON_FALSE_POSITIVE_STOPLIST:
                continue
            if len(name.split()) < 2:
                continue
            s = m.start(1)
            e = s + len(name)
            spans.append(PiiSpan(s, e, text[s:e], "PERSON"))

        for m in LEGAL_PERSON_CONTEXT_RE.finditer(text):
            name = m.group(1).strip().rstrip(",")
            norm_name = re.sub(r"\s+", " ", name.lower())
            if norm_name in DEFINED_TERM_STOPLIST or norm_name in PERSON_FALSE_POSITIVE_STOPLIST:
                continue
            if len(name.split()) < 2:
                continue
            s, e = m.start(1), m.end(1)
            spans.append(PiiSpan(s, e, text[s:e], "PERSON"))

        for m in CONTACT_PERSON_FIELD_RE.finditer(text):
            field_start = m.start(1)
            for name in _extract_contact_names(m.group(1)):
                rel = m.group(1).find(name)
                if rel < 0:
                    continue
                s = field_start + rel
                spans.append(PiiSpan(s, s + len(name), text[s:s + len(name)], "PERSON"))

        return spans

    def _find_trademark_alias(self, text: str) -> List[PiiSpan]:
        """Detect KSH trademark/company references when context indicates it."""
        spans = []
        # Trademark KSH is only established if KSH International has been registered
        has_ksh_international = any("ksh international" in name.lower() for name in self.company_registry)
        if not has_ksh_international:
            return spans

        # Check if the paragraph text is exactly "KSH" (isolated table cell/bullet)
        if text.strip() == "KSH":
            spans.append(PiiSpan(0, len(text), text, "COMPANY"))
            return spans

        # Regex context matching
        KSH_CONTEXT_RE = re.compile(
            r"\b(KSH)\s+(?:Group|Scheme|Employee|Project|Infra|Distriparks|Integrated|Logistics|Motors|International|Chakan|Kamgar)\b"
            r"|(?i:trademark|brand|mark|registered)\s+[\"\'“]?(KSH)[\"\'”]?\b"
            r"|[\"\'“](KSH)[\"\'”]"
            r"|\b(?:of|promoter\s+of|by|shares\s+of|to)\s+(KSH)\b"
        )
        for m in KSH_CONTEXT_RE.finditer(text):
            for g_idx in range(1, 5):
                val = m.group(g_idx)
                if val == "KSH":
                    s = m.start(g_idx)
                    e = m.end(g_idx)
                    spans.append(PiiSpan(s, e, "KSH", "COMPANY"))
                    break
        return spans

    @staticmethod
    def _remove_overlaps(spans: List[PiiSpan]) -> List[PiiSpan]:
        """Keep the longest span when spans overlap; structured (regex)
        matches take priority over NER for the same region."""
        priority = {"EMAIL": 0, "SSN": 0, "CREDIT_CARD": 0, "IP": 0, "PHONE": 0,
                    "DOB": 0, "ADDRESS": 1, "PERSON": 2, "COMPANY": 2, "URL": 3}
        spans = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
        result: List[PiiSpan] = []
        occupied: List[Tuple[int, int]] = []
        # process highest priority (lowest number) first; within a priority
        # tier, prefer the longer span so e.g. a full registered person name
        # wins over an accidental shorter overlapping match.
        for s in sorted(spans, key=lambda s: (priority.get(s.label, 9), -(s.end - s.start), s.start)):
            if any(not (s.end <= o[0] or s.start >= o[1]) for o in occupied):
                continue
            occupied.append((s.start, s.end))
            result.append(s)
        return sorted(result, key=lambda s: s.start)

    def find_spans(self, text: str) -> List[PiiSpan]:
        spans = self._find_structured(text)
        spans += self._find_address(text)
        if self.person_registry or self.company_registry:
            # Registry-driven pass (post pass-1): use confirmed entities for
            # consistent, document-wide PERSON/COMPANY detection instead of
            # re-asking spaCy for an independent judgment on this paragraph.
            spans += self._registry_spans(text)
        else:
            # No registry built (e.g. redact() called standalone/pass 1) --
            # fall back to plain per-paragraph NER.
            spans += self._find_ner(text)
        
        # Contextual trademark/alias matches (runs after registry passes to ensure cross-paragraph context is available)
        spans += self._find_trademark_alias(text)

        return self._remove_overlaps(spans)

    # -- redaction -------------------------------------------------------

    def redact(self, text: str) -> Tuple[str, List[PiiSpan]]:
        spans = self.find_spans(text)
        out = []
        last = 0
        for s in spans:
            out.append(text[last:s.start])
            out.append(self.factory.get(s.label, s.text))
            last = s.end
        out.append(text[last:])
        return "".join(out), spans
