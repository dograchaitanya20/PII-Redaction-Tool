"""
Applies PiiRedactor to every paragraph in a .docx file (main body, and all
table cells, including nested tables), writes a redacted copy, and logs
every redaction made (type + before/after) to a CSV/JSON audit trail.

Formatting note: a paragraph's text is redacted as a whole string, then
written back into the paragraph's first run (remaining runs cleared). This
keeps paragraph-level styling (font, size, bold-as-whole-paragraph, cell
shading, table layout) but does not preserve run-level formatting that
varies *within* a single paragraph (e.g. only one word bolded). See
README.md for the full discussion of this tradeoff.
"""

import sys
import csv
import json
import docx
from docx.document import Document as DocxDocument
from docx.table import Table
from docx.text.paragraph import Paragraph

from redactor import PiiRedactor


def iter_paragraphs(parent, _seen_tcs=None):
    """Yield every Paragraph in the document body and inside every table
    cell, recursing into nested tables.

    IMPORTANT: python-docx's Table.rows[i].cells returns the SAME Cell
    wrapper (same underlying <w:tc> element) once per spanned grid column
    for horizontally-merged cells. Without deduplication, a paragraph
    inside a merged cell gets yielded -- and redacted -- once per spanned
    column, corrupting output on the 2nd+ pass and double-counting every
    redaction in that cell.

    CORRECTNESS NOTE: the dedup below tracks visited <w:tc> elements by
    identity. An earlier version of this function tracked identity via a
    bare `set()` of `id(cell._tc)` integers. That is unsafe: `Cell` wrapper
    objects (and their `_tc` proxies) are created transiently on each
    `row.cells` access, and nothing else keeps them alive -- storing only
    the integer id() does not prevent garbage collection. When a transient
    object is collected, CPython can reuse its memory address for a later,
    completely unrelated object, so an unrelated cell can end up with the
    SAME id() as an earlier, already-seen one purely by allocator
    coincidence. That earlier version was verified (empirically, by diffing
    repeated runs against the same unmodified input file) to silently skip
    different, real paragraphs on different runs -- non-deterministic data
    loss with no error or warning. Keeping a set of the actual `_tc` OBJECTS
    (not their ids) holds a strong reference for the lifetime of the
    traversal, which keeps their memory addresses stable and makes identity
    comparison correct.
    """
    if _seen_tcs is None:
        _seen_tcs = set()

    if isinstance(parent, DocxDocument):
        parent_elm = parent.element.body
    else:
        parent_elm = parent._element

    for child in parent_elm.iterchildren():
        if child.tag.endswith('}p'):
            yield Paragraph(child, parent)
        elif child.tag.endswith('}tbl'):
            table = Table(child, parent)
            for row in table.rows:
                for cell in row.cells:
                    tc = cell._tc
                    already_seen = any(tc is seen for seen in _seen_tcs)
                    if already_seen:
                        continue  # merged cell already processed via an earlier column
                    _seen_tcs.add(tc)
                    yield from iter_paragraphs(cell, _seen_tcs)


def redact_paragraph(paragraph: Paragraph, redactor: PiiRedactor, log: list):
    original = paragraph.text
    if not original or not original.strip():
        return
    redacted, spans = redactor.redact(original)
    if spans:
        for s in spans:
            log.append({
                "type": s.label,
                "original": s.text,
                "fake": redactor.factory.get(s.label, s.text),
            })
    if redacted != original and paragraph.runs:
        paragraph.runs[0].text = redacted
        for run in paragraph.runs[1:]:
            run.text = ""


def main(in_path, out_path, log_csv_path, log_json_path):
    document = docx.Document(in_path)
    redactor = PiiRedactor()
    log = []

    # Materialize the full paragraph list BEFORE mutating anything. iter_paragraphs
    # is a lazily-evaluated generator walking the live lxml tree; interleaving
    # mutation (redact_paragraph rewrites run text) with traversal of that same
    # tree is undefined behaviour and was observed to make the paragraph count
    # non-deterministic between runs. Two clean passes -- collect, then mutate --
    # avoids that entirely.
    paragraphs = list(iter_paragraphs(document))

    # PASS 1 -- build a document-wide entity registry (confirmed PERSON /
    # COMPANY strings) BEFORE any replacement happens. This is what makes
    # redaction consistent: a name recognized anywhere in the document gets
    # redacted everywhere, not just in the paragraphs where spaCy's
    # per-sentence NER happened to recognize it. See redactor.PiiRedactor
    # docstring for the full rationale.
    for paragraph in paragraphs:
        text = paragraph.text
        if text and text.strip():
            redactor.register_text(text)
    print(f"Registry built: {len(redactor.person_registry)} person(s), "
          f"{len(redactor.company_registry)} compan(y/ies)")

    # PASS 2 -- apply replacements using the frozen registry + regex
    # detectors. Detection runs once against the ORIGINAL paragraph text
    # only; generated fake values are never fed back through detection, so
    # they cannot be "redacted again" on a later pass.
    count = 0
    for paragraph in paragraphs:
        redact_paragraph(paragraph, redactor, log)
        count += 1

    document.save(out_path)

    with open(log_csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "original", "fake"])
        w.writeheader()
        w.writerows(log)

    with open(log_json_path, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2, ensure_ascii=False)

    by_type = {}
    for row in log:
        by_type[row["type"]] = by_type.get(row["type"], 0) + 1

    print(f"Paragraphs processed: {count}")
    print(f"Total redactions: {len(log)}")
    for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t}: {c}")


if __name__ == "__main__":
    in_path = sys.argv[1]
    out_path = sys.argv[2]
    log_csv = sys.argv[3] if len(sys.argv) > 3 else "redaction_log.csv"
    log_json = sys.argv[4] if len(sys.argv) > 4 else "redaction_log.json"
    main(in_path, out_path, log_csv, log_json)
