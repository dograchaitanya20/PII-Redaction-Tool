#!/usr/bin/env python3
"""
Single entry point for the PII redaction pipeline.

Usage:
    python3 run.py redact                      # input/Red_Herring_Prospectus.docx -> output/..._REDACTED.docx
    python3 run.py redact in.docx out.docx      # explicit paths
    python3 run.py evaluate                     # runs evaluation/evaluate.py, prints + writes eval_summary.json

Setup (see README.md for details):
    pip install -r requirements.txt
    python3 -m spacy download en_core_web_sm
"""
import sys
import os
import runpy

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))


def cmd_redact(argv):
    import docx_processor  # src/docx_processor.py, on sys.path via ROOT/src

    default_in = os.path.join(ROOT, "input", "Red_Herring_Prospectus.docx")
    default_out = os.path.join(ROOT, "output", "Red_Herring_Prospectus_REDACTED.docx")
    in_path = argv[0] if len(argv) > 0 else default_in
    out_path = argv[1] if len(argv) > 1 else default_out

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    logs_dir = os.path.join(ROOT, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    log_csv = os.path.join(logs_dir, "redaction_log.csv")
    log_json = os.path.join(logs_dir, "redaction_log.json")

    docx_processor.main(in_path, out_path, log_csv, log_json)
    print(f"\nRedacted file: {out_path}")
    print(f"Redaction log: {log_csv}")


def cmd_validate(argv):
    import validate  # src/validate.py

    default_orig = os.path.join(ROOT, "input", "Red_Herring_Prospectus.docx")
    default_redacted = os.path.join(ROOT, "output", "Red_Herring_Prospectus_REDACTED.docx")
    orig = argv[0] if len(argv) > 0 else default_orig
    redacted = argv[1] if len(argv) > 1 else default_redacted
    sys.exit(validate.main(orig, redacted))


def cmd_evaluate():
    eval_dir = os.path.join(ROOT, "evaluation")
    sys.path.insert(0, eval_dir)
    old_cwd = os.getcwd()
    os.chdir(eval_dir)  # evaluate.py reads its json fixtures via relative paths
    try:
        runpy.run_path(os.path.join(eval_dir, "evaluate.py"), run_name="__main__")
    finally:
        os.chdir(old_cwd)


if __name__ == "__main__":
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    if len(sys.argv) < 2 or sys.argv[1] not in ("redact", "evaluate", "validate"):
        print(__doc__)
        sys.exit(1)
    if sys.argv[1] == "redact":
        cmd_redact(sys.argv[2:])
    elif sys.argv[1] == "validate":
        cmd_validate(sys.argv[2:])
    else:
        cmd_evaluate()

