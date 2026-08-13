"""
Computes evaluation metrics for PiiRedactor against:
  1. A hand-labeled 120-paragraph random sample drawn from the real
     Red Herring Prospectus (ground_truth_sample.json / sample_paragraphs.json)
  2. A synthetic sentence set covering PII types absent from the real
     document -- SSN, credit card, IP, DOB -- plus distractor numbers
     (order #, ticket #, reference ID) to test precision (synthetic_eval_set.json)

For each, reports:
  - Entity-level precision / recall / F1, per PII type and overall
    (label must match; text match is fuzzy -- substring or >60% similarity,
    since exact character-offset agreement is not the interesting question
    here, "was the right thing caught" is)
  - Paragraph/sentence-level accuracy, precision, recall (did we correctly
    predict whether a chunk contains ANY PII at all)
"""

import json
import difflib
import re
from collections import defaultdict

from redactor import PiiRedactor


def norm(s: str) -> str:
    s = s.lower().strip()
    s = s.replace("\u2013", "-").replace("\u2014", "-")
    s = re.sub(r"\s+", " ", s)
    return s


def fuzzy_match(a: str, b: str) -> bool:
    a, b = norm(a), norm(b)
    if not a or not b:
        return False
    if a in b or b in a:
        return True
    return difflib.SequenceMatcher(None, a, b).ratio() > 0.6


def score_entities(gt_items, pred_items):
    """gt_items / pred_items: list of (label, text). Greedy one-to-one
    matching by label + fuzzy text match."""
    matched_pred = set()
    tp = []
    fn = []
    for g_label, g_text in gt_items:
        found = None
        for i, (p_label, p_text) in enumerate(pred_items):
            if i in matched_pred:
                continue
            if p_label == g_label and fuzzy_match(g_text, p_text):
                found = i
                break
        if found is not None:
            matched_pred.add(found)
            tp.append((g_label, g_text))
        else:
            fn.append((g_label, g_text))
    fp = [pred_items[i] for i in range(len(pred_items)) if i not in matched_pred]
    return tp, fn, fp


def evaluate_real_sample(redactor):
    sample = json.load(open("sample_paragraphs.json", encoding="utf-8"))
    gt = json.load(open("ground_truth_sample.json", encoding="utf-8"))

    # Mirror the real pipeline (docx_processor.main): build the entity
    # registry from all sample paragraphs BEFORE scoring any of them, so
    # this evaluation reflects the same registry-driven, document-wide
    # consistency behaviour that redact_document actually uses -- not a
    # weaker paragraph-isolated version of it.
    for text in sample:
        redactor.register_text(text)

    per_type = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    para_tp = para_fn = para_fp = para_tn = 0

    for idx, text in enumerate(sample):
        gt_items = [tuple(x) for x in gt.get(str(idx), [])]
        spans = redactor.find_spans(text)
        pred_items = [(s.label, s.text) for s in spans]

        tp, fn, fp = score_entities(gt_items, pred_items)
        for l, _ in tp:
            per_type[l]["tp"] += 1
        for l, _ in fn:
            per_type[l]["fn"] += 1
        for l, _ in fp:
            per_type[l]["fp"] += 1

        has_gt = len(gt_items) > 0
        has_pred = len(pred_items) > 0
        if has_gt and has_pred:
            para_tp += 1
        elif has_gt and not has_pred:
            para_fn += 1
        elif not has_gt and has_pred:
            para_fp += 1
        else:
            para_tn += 1

    return per_type, (para_tp, para_fn, para_fp, para_tn, len(sample))


def evaluate_synthetic(redactor):
    data = json.load(open("synthetic_eval_set.json", encoding="utf-8"))
    for item in data:
        redactor.register_text(item["text"])

    per_type = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    para_tp = para_fn = para_fp = para_tn = 0

    for item in data:
        gt_items = [(e["label"], e["text"]) for e in item["entities"]]
        spans = redactor.find_spans(item["text"])
        pred_items = [(s.label, s.text) for s in spans]

        tp, fn, fp = score_entities(gt_items, pred_items)
        for l, _ in tp:
            per_type[l]["tp"] += 1
        for l, _ in fn:
            per_type[l]["fn"] += 1
        for l, _ in fp:
            per_type[l]["fp"] += 1

        has_gt = len(gt_items) > 0
        has_pred = len(pred_items) > 0
        if has_gt and has_pred:
            para_tp += 1
        elif has_gt and not has_pred:
            para_fn += 1
        elif not has_gt and has_pred:
            para_fp += 1
        else:
            para_tn += 1

    return per_type, (para_tp, para_fn, para_fp, para_tn, len(data))


def prf(tp, fn, fp):
    p = tp / (tp + fp) if (tp + fp) else float("nan")
    r = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * p * r / (p + r) if (p + r) and p == p and r == r and (p + r) > 0 else float("nan")
    return p, r, f1


def print_report(name, per_type, para_stats):
    print(f"\n=== {name}: entity-level ===")
    tot_tp = tot_fn = tot_fp = 0
    for label in sorted(per_type):
        d = per_type[label]
        p, r, f1 = prf(d["tp"], d["fn"], d["fp"])
        tot_tp += d["tp"]; tot_fn += d["fn"]; tot_fp += d["fp"]
        print(f"  {label:12s} TP={d['tp']:3d} FN={d['fn']:3d} FP={d['fp']:3d}  "
              f"P={p:.3f} R={r:.3f} F1={f1:.3f}")
    p, r, f1 = prf(tot_tp, tot_fn, tot_fp)
    print(f"  {'OVERALL':12s} TP={tot_tp:3d} FN={tot_fn:3d} FP={tot_fp:3d}  "
          f"P={p:.3f} R={r:.3f} F1={f1:.3f}")

    tp, fn, fp, tn, n = para_stats
    acc = (tp + tn) / n
    p2, r2, _ = prf(tp, fn, fp)
    print(f"\n=== {name}: chunk-level (contains-PII classification) ===")
    print(f"  N={n}  TP={tp} FN={fn} FP={fp} TN={tn}")
    print(f"  Accuracy={acc:.3f}  Precision={p2:.3f}  Recall={r2:.3f}")
    return dict(entity_tp=tot_tp, entity_fn=tot_fn, entity_fp=tot_fp,
                entity_p=p, entity_r=r, entity_f1=f1,
                chunk_n=n, chunk_tp=tp, chunk_fn=fn, chunk_fp=fp, chunk_tn=tn,
                chunk_acc=acc, chunk_p=p2, chunk_r=r2)


if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    # Separate PiiRedactor instances -- these are two independent test sets
    # (real document sample vs. synthetic sentences for types the real doc
    # doesn't contain), and each needs its own document-wide entity
    # registry built from only its own text. Sharing one instance would let
    # the real sample's registry "leak" into synthetic scoring and vice
    # versa (registry-driven detection would only look for names it has
    # already seen, silently tanking recall on unrelated names).
    redactor_real = PiiRedactor()
    per_type_real, para_real = evaluate_real_sample(redactor_real)
    summary_real = print_report("Real prospectus sample (n=120 paragraphs)", per_type_real, para_real)

    redactor_syn = PiiRedactor()
    per_type_syn, para_syn = evaluate_synthetic(redactor_syn)
    summary_syn = print_report("Synthetic test set (n=20 sentences)", per_type_syn, para_syn)

    with open("eval_summary.json", "w", encoding="utf-8") as f:
        json.dump({"real_sample": summary_real, "synthetic": summary_syn}, f, indent=2)
