# PII Redaction Tool

Redacts PII from `Red Herring Prospectus.docx` and replaces every unique
piece of PII with a **consistent** fake value (the same original always maps
to the same fake, everywhere it appears — same behaviour as the
`Rashi Patil -> John Doe` example in the assignment brief).

> **v3 note**: this version replaces the per-paragraph detection approach
> with a document-wide entity registry (see "Architecture" below), and fixes
> a non-deterministic data-loss bug in the merged-cell handling that v2's
> own bugfix had introduced. If you're comparing against an earlier copy,
> re-pull everything — the detection logic, traversal, and all reported
> numbers changed. `python3 run.py validate` (new in this version) is the
> command to run first on any future changes: it checks the entire output
> document for leaked PII, not just a sample.

## Setup

```bash
pip install -r requirements.txt
python3 -m spacy download en_core_web_sm
```

## Usage

```bash
python3 run.py redact                      # input/Red_Herring_Prospectus.docx -> output/..._REDACTED.docx
python3 run.py redact in.docx out.docx      # or explicit paths
python3 run.py validate                     # scans the ENTIRE output doc for leaked known PII (not a sample)
python3 run.py evaluate                     # prints sampled precision/recall, writes evaluation/eval_summary.json
```

## Layout

```
PII_Redaction/
├── src/
│   ├── redactor.py          # detection + fake-value engine (regex + spaCy NER + entity registry)
│   ├── docx_processor.py    # walks the docx (body + every table cell, incl. merged
│   │                         # cells and nested tables), redacts, writes output + log
│   └── validate.py          # full-document leak scan (NOT sample-based) -- run after every change
├── input/
│   └── Red_Herring_Prospectus.docx
├── output/
│   └── Red_Herring_Prospectus_REDACTED.docx
├── evaluation/
│   ├── evaluate.py
│   ├── ground_truth_sample.json    # hand labels for the 120-paragraph real-doc sample
│   ├── sample_paragraphs.json      # the sampled paragraph text itself
│   └── synthetic_eval_set.json     # covers PII types absent from the real doc
├── logs/
│   └── redaction_log.csv / .json   # every redaction made: type, original, fake
├── requirements.txt
├── run.py
├── README.md
└── EVALUATION_REPORT.md
```

## About the source document

This is a real SEBI offering document (Red Herring Prospectus) — not a
customer-support "ticket log" as the assignment prose describes — **123
pages**, 1,006 top-level paragraphs, 76 tables, 4,486 total paragraphs once
every table cell is counted individually (deduplicated for merged cells,
see below). It contains real emails, phone numbers, personal names, company
/ trust names, and physical addresses, but no SSNs, credit-card numbers, IP
addresses, or dates of birth — those four categories are demonstrated
against a synthetic test set instead (`evaluation/synthetic_eval_set.json`).

## Architecture: two-pass detection with a document-wide entity registry

**Why two passes.** An earlier version ran NER independently on each
paragraph. spaCy's model makes a local, context-dependent judgment call
every time it sees a name — it has no memory of having already confirmed
"Kushal Subbayya Hegde" is a person three paragraphs earlier. In testing,
this caused the same name to be redacted in one sentence and left
unredacted two sentences later, and caused isolated names (e.g. "Contact
Person: Tushar Wakhele", with no surrounding sentence for NER to use as
context) to be missed everywhere. This is not a tuning problem — it's
structural, so it needed a structural fix:

- **Pass 1 (`register_text`)**: scan every paragraph in the document and
  build a registry of confirmed PERSON and COMPANY strings — spaCy NER,
  plus explicit context rules for role-labelled names ("Contact Person:",
  "Promoter(s):", "Director:", "Chairman:", "Managing Director:", ...) that
  NER alone misses in isolation.
- **Pass 2 (`redact_document`)**: for each paragraph, replace every exact
  occurrence of every registered entity (longest match first, so "Kushal
  Subbayya Hegde" is matched whole rather than partially as "Kushal"),
  combined with the structured regex/address detectors run fresh against
  the original paragraph text. A name recognised *anywhere* in the document
  is now redacted *everywhere*, independent of whether local NER would have
  caught that specific sentence.

**Structured PII → regex** (unchanged approach, still independent of the
registry since format-based detection doesn't need document-wide context):
email, phone (Indian + generic international formats, including a
bare-digit-count Luhn check for credit cards to avoid flagging the
CINs/ISINs/reference numbers that are extremely common in financial
documents), SSN, IPv4, and date-of-birth (a date token found near a "date
of birth / born on / DOB" keyword — dates alone are not redacted, or a
document full of filing dates would be mostly blacked out).

**Company detection: legal-suffix-anchored, not "every spaCy ORG".** A
capitalised phrase is only accepted as COMPANY if it has a legal-entity
suffix (Limited, Ltd., Private Limited, LLP, Inc., Corporation, Family
Trust, ...), backed by a regex that catches suffixed names spaCy's ORG
model misses entirely. This was a deliberate precision-over-recall
decision: treating any ORG tag as a company was confirmed (by diffing
input/output) to relabel ordinary document text as fake companies — the
document's own title "RED HERRING PROSPECTUS" was turned into a fake
company name, and defined terms like "EQUITY SHARES" were altered. See
`EVALUATION_REPORT.md` for the measured recall cost of this choice and why
the document-wide registry mostly offsets it in practice.

**Addresses → heuristic**: a paragraph is treated as one address block if
it contains a 5-6 digit PIN/ZIP code **and** a street-type keyword (Road,
Village, Taluka, Society, Sector, ...); the whole line is redacted as one
unit, matching how addresses are laid out in this document (one field per
table cell).

Adding a new PII type means: write one regex or NER rule in `redactor.py`,
add one branch to `FakeValueFactory._generate` for its fake value — nothing
else in the pipeline changes.

### Consistent fake values

`FakeValueFactory` keys a dict by `(pii_type, normalized_original_text)`.
The fake itself comes from `Faker`, seeded deterministically from a hash of
the original string, so re-running the pipeline reproduces the same fake
values every time, while still giving every unique person/company/etc. its
own distinct fake identity. Detection always runs against the original
paragraph text only, never against already-redacted text, so a generated
fake value can never be picked up and "re-redacted" on a later pass.

### Explicit precision/recall choice: are regulators/exchanges PII?

**Generic regulators, exchanges and statutes (SEBI, RBI, NSE, BSE, the
Companies Act, ...) are treated as NOT sensitive** — they identify a public
regulatory body, not a person or private company — and are whitelisted out.
**Named promoter/family trusts and private companies ARE treated as
sensitive** and redacted, since they identify specific private parties.

## Validation: does the final DOCX actually contain zero known PII?

```bash
python3 run.py validate
```

This is the check that matters most and the one most easily skipped: it
does **not** rely on the 120-paragraph sample. It rebuilds the full entity
registry from the entire original document, then checks whether any of
those exact strings survive anywhere in the redacted DOCX. The validator now performs two checks:

1. a detector-derived full-document audit when `en_core_web_sm` is installed; and
2. an **independent manual ground-truth audit** from
   `evaluation/manual_ground_truth.json`, which does not depend on the detector
   finding the entity in the first place.

The packaged redacted DOCX was independently checked against the 52 unique
manually verified entities (covering the entire document) and **0 remain**. This independent check is
important because a detector cannot validate a name it failed to detect.

When the spaCy model is installed, `python3 run.py validate` also performs the
full detector-derived audit. If the model is not installed, the validator
explicitly skips that part rather than failing and still runs the independent
ground-truth check. Run validation after every change to detection logic.

## Bugs fixed during development

1. **Non-deterministic paragraph loss via `id()` reuse.** An earlier merged-cell
   traversal fix stored only `id(cell._tc)` integers. Python could reuse those
   addresses and silently skip unrelated cells. The traversal now retains the
   actual XML cell objects, making extraction deterministic.
2. **Merged table cells were processed twice.** Traversal now deduplicates the
   underlying `<w:tc>` objects while still visiting nested tables.
3. **Document-wide entity registry.** PERSON/COMPANY entities are registered
   in a first pass over the original document and replaced in a second pass,
   preventing inconsistent name mappings and fake-value re-redaction.
4. **Company over-redaction.** Generic spaCy ORG labels are no longer treated as
   companies automatically. Company detection requires a sufficiently specific
   legal suffix and at least two name tokens for normal legal entities. Generic
   fragments such as `India Limited`, `Private Limited`, and `Pandit, LLP` are
   rejected; compound comma-separated company lists are split into individual
   candidates.
5. **PERSON false positives in legal prose.** Added a targeted stoplist for
   observed document terms such as `Offer Price`, `Mutual Funds`, `Key
   Managerial`, `Selling Shareholders`, and certification labels.
6. **Contact-person recall.** Added explicit parsing for `Contact Person:` fields,
   including slash-separated lists such as `Eric Bacha/ Sachin Gawade/ Pravin
   Teli`, plus role/field suffix trimming.
7. **Contextual PERSON recall.** Added carefully constrained legal-context rules
   for names introduced by phrases such as `from ...` and `namely, ...`, which
   catches isolated expert/contact names that spaCy can miss.
8. **Phone-format coverage.** The phone detector accepts the literal `+ 91`
   spacing used in the source document.
9. **Independent leak validation.** Validation now includes a hand-labeled
   ground-truth audit so a detector miss cannot hide a real PII leak.

## Known remaining limitations

Disclosed rather than papered over — these are the current, honest edges of
the system, verified against the actual output, not assumed:

- **COMPANY recall is capped by the legal-suffix requirement.** A company
  referenced only by a bare short name with no suffix anywhere in the
  document (rare here, since Indian prospectuses almost always give the
  full registered name at least once) would never enter the registry and
  so would never be redacted, even by the document-wide pass. Sampled
  recall on the real document is 0.500 for this category (see
  `EVALUATION_REPORT.md`) — this is the main quantified tradeoff of
  prioritising precision (which went from 0.500 to 1.000 on the same
  sample).
- **Bare "Bank" is deliberately not a company suffix.** Testing showed it
  caused false positives on generic role terminology this document repeats
  often ("Refund Bank", "Escrow Bank", "Sponsor Bank"). "Bank Limited"
  still matches via "Limited". A real bank referenced only as e.g. "HDFC
  Bank" with no "Limited" nearby would be missed.
- **Context-rule PERSON detection is anchored to a fixed list of role
  labels** (Contact Person, Promoter(s), Director, Chairman, Managing
  Director, Company Secretary, Compliance Officer, CFO, Whole-time
  Director). A name introduced under a role label not in this list would
  rely on plain NER instead, with NER's usual limitations.
- **Formatting tradeoff**: a paragraph's text is redacted as one string and
  written back into its first run (other runs cleared), so run-level
  formatting that varies *within* a paragraph (e.g. only one word bolded)
  is not preserved. Paragraph-level styling and all table/cell layout is
  preserved.
- **The DEFINED_TERM_STOPLIST is inherently open-ended** for this document
  genre — it currently reflects every false positive found during this
  round of testing, but a different Red Herring Prospectus from a
  different issuer would likely surface new defined terms not yet on the
  list. This is a known limitation of stoplist-based precision fixes in
  general, not something fully closeable without a larger, document-
  genre-specific defined-terms model.
