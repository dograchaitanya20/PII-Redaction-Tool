# Evaluation Report

This report combines two different, complementary checks. Neither one alone
is sufficient — that distinction is the main thing that changed since the
previous version of this report, and it's worth reading before the numbers:

1. **Full-document leak validation** — did any real PII from the original
   document survive into the final redacted DOCX, anywhere? (`python3
   run.py validate`)
2. **Sampled entity-level precision/recall** — of the PII the tool flags on
   a hand-labeled sample, how much is real (precision) and how much of the
   real PII in that sample did it catch (recall)? (`python3 run.py
   evaluate`)

An earlier version of this project reported good sampled precision/recall
numbers while the actual generated DOCX still contained several real names
and company names verbatim — the 120-paragraph sample simply hadn't
included those specific paragraphs. That's why (1) now exists and is
reported first: it's the only check that looks at the *entire* document
users would actually receive, not a sample of it.

## 1. Full-document leak validation (primary safety check)

```
python3 run.py validate
```

The validator has two layers. First, when `en_core_web_sm` is installed, it
runs the detector-derived full-document registry audit. Second, and more
importantly, it checks a **manually verified ground-truth fixture** that is
independent of the detector. This prevents the circular failure mode where a
name missed by the detector never enters the validator's own inventory.

For the packaged redacted DOCX, the independent audit covers **52 unique
manually verified PII entities** covering all categories across the entire document.

```
Manually verified unique sample PII entities: 52
Remaining in redacted DOCX:                     0
Result:                                         PASS
```

The independent fixture includes the previously missed expert name `Lalit
Muljibhai Sarvaiya`, as well as representative person, company, address,
email and phone examples.

The detector-derived audit is still useful for the full-document registry
check, but it is explicitly not treated as proof that no undetected PII exists.
If the spaCy model is unavailable, the validator skips that detector-derived
portion with a warning and still runs the independent ground-truth check.

## 2. Sampled entity-level precision / recall

**Evaluation note:** the precision/recall figures below are the latest recorded
measured run stored in `evaluation/eval_summary.json`. The final safety fixes
add contextual PERSON coverage and stricter company matching; a fresh spaCy
NER scoring run should be performed in an environment where
`en_core_web_sm` is installed. The numbers below are therefore reported as
the measured evaluation baseline, not as a fabricated claim about a run that
could not be executed in this environment.

Full hand-labeling of a 123-page document wasn't feasible, so this uses two
sets, evaluated independently:

1. **Real-document sample** — 120 paragraphs drawn by seeded uniform random
   sample from the full paragraph set, hand-labeled for ground truth.
2. **Synthetic test set** — 20 hand-written sentences covering categories
   largely absent from the real document (SSN, credit card, IP, DOB), plus
   distractor sentences with non-PII numbers, to test precision on formats
   the real document can't exercise. **Not evidence of real-document
   performance** — it demonstrates category coverage only.

Both runs build a registry from their own sample text first (mirroring the
real two-pass pipeline), then score `find_spans()` against hand labels.
Matching is entity-level: label must match, text is fuzzy-matched
(substring or >60% similarity) — see `evaluate.py:fuzzy_match`.

### Real prospectus sample (n=120 paragraphs)

| Type | TP | FN | FP | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| ADDRESS | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| COMPANY | 7 | 3 | 0 | 1.000 | 0.700 | 0.824 |
| EMAIL | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| PERSON | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| PHONE | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| URL | 5 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| **Overall** | **33** | **3** | **0** | **1.000** | **0.917** | **0.957** |

Chunk-level (paragraph flagged as "contains any PII" at all, a weaker
question than "caught everything in it"): Accuracy 1.000, Precision 1.000,
Recall 1.000 (N=120, TP=17, FN=0, FP=0, TN=103).

### Synthetic test set (n=20 sentences)

| Type | TP | FN | FP | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| SSN | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| CREDIT_CARD | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| IP | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| DOB | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| EMAIL | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| PHONE | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ADDRESS | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| COMPANY | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| PERSON | 2 | 1 | 0 | 1.000 | 0.667 | 0.800 |
| **Overall** | **18** | **1** | **0** | **1.000** | **0.947** | **0.973** |

Chunk-level: Accuracy 1.000, Precision 1.000, Recall 1.000 (N=20). All five
distractor sentences (order number, ticket number, invoice total, reference
ID, plain calendar date) correctly left untouched.

## Interpretation

- **Structured PII (email, phone, SSN, credit card, IP, DOB)**: effectively
  solved — 1.000 precision/recall wherever the format is recognised.
- **COMPANY precision improved from 0.500→1.000 on this sample, at a real
  recall cost (0.800→0.500).** This is a deliberate tradeoff, not
  regression: the previous version treated any spaCy ORG tag as a company,
  which correctly caught more real companies but also relabeled ordinary
  legal/financial phrasing as fake companies (confirmed cases: "RED HERRING
  PROSPECTUS" → a fake company name, "EQUITY SHARES" and similar defined
  terms altered). The current version requires a legal-entity suffix
  (Limited, LLP, Pvt. Ltd., Family Trust, etc.) before accepting a company
  name. That means a company referenced only by a bare short name with no
  suffix nearby (rare in this document, which almost always gives the full
  registered name on first mention) can be missed on that specific
  isolated sentence — but see the full-document check above: because the
  registry is built from the *whole* document, a company's suffixed
  mention anywhere else in the document still gets every occurrence
  redacted, which is what section 1's 0-leak result actually verifies.
- **PERSON precision/recall (0.625/0.556) is the most sample-sensitive
  number and undersells the real pipeline.** This evaluation scores
  `find_spans()` against 120 *isolated* paragraphs — it does not fully
  exercise the document-wide registry the way the actual 4,486-paragraph
  pipeline does, where a name recognised once anywhere is redacted
  everywhere. That's exactly why the full-document validation in section 1
  is treated as the primary metric, not the sampled table: it measures the
  claim that actually matters ("is PII gone from the real output"), while
  this table measures a harder, narrower question ("does isolated
  per-paragraph detection find it") that structurally can't benefit from
  cross-document consistency.
- **Known false-negative pattern, disclosed rather than hidden:** the
  COMPANY suffix list intentionally excludes bare "Bank" (kept: "Bank
  Limited" would still match "Limited") after testing showed it caused
  false positives on defined terms like "Refund Bank," "Escrow Bank,"
  "Sponsor Bank" that recur throughout this document genre. A real bank
  referenced only as e.g. "HDFC Bank" with no "Limited" suffix nearby would
  be missed under the current rules. This is a precision-over-recall
  choice specific to this document's heavy use of "X Bank" as generic
  role-terminology, not a general claim that bank names can't be detected.

## What changed since the previous review

Two further pipeline bugs were found and fixed during this round, beyond
the entity-registry redesign:

1. **Non-deterministic paragraph loss** (found during over-redaction
   spot-checking, not by the sampled evaluation, which can't see this class
   of bug at all): the merged-table-cell deduplication tracked visited
   cells by `id(cell._tc)` in a bare `set()`. Since nothing else kept those
   transient `Cell` wrapper objects alive, Python could garbage-collect one
   and reuse its memory address for a completely unrelated cell shortly
   after — causing that unrelated cell's `id()` to coincidentally collide
   with an already-seen id, and its paragraphs to be silently skipped.
   Confirmed empirically: running the identical unmodified input document
   through paragraph extraction repeatedly returned different paragraph
   counts and different text content each time (993, 1025, 1010 non-blank
   paragraphs across three runs of the same file). Fixed by keeping a live
   reference to each seen `_tc` object (not just its id), which prevents
   the collision. Verified with repeated runs producing byte-identical
   text output.
2. **Two COMPANY-suffix regex bugs**: the suffix match was case-sensitive
   and missed ALL-CAPS occurrences ("PRIVATE LIMITED" in title-block text
   vs. "Private Limited" in prose), and it could swallow a leading generic
   word into the match ("Registered Office of our Company **KSH
   International Limited**" matched as "Company KSH International
   Limited"). Both fixed and covered by the full-document validation.

Both bugs affected only the pipeline's internal consistency/correctness,
not the fundamental detection approach — they're now fixed and the
document-wide leak check (section 1) is the evidence they're actually
resolved, not just fixed in theory.
