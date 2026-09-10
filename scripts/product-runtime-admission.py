#!/usr/bin/env python3
"""Validate or sign a fixed Product candidate; never starts Product runtimes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from product_runtime.evidence import EvidenceError, EvidenceStore
from product_runtime.models import AdmissionError
from product_runtime.signing import sign_verified, verify_request


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify", "sign"))
    parser.add_argument(
        "--request", required=True, help="Relative JSON file inside evidence root"
    )
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--shadow-key-file", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args(argv)
    signing_options = (args.key_file, args.shadow_key_file, args.output_dir)
    if args.operation == "verify" and any(signing_options):
        parser.error("verify does not accept key or output arguments")
    if args.operation == "sign" and not all(signing_options):
        parser.error("sign requires key-file, shadow-key-file and output-dir")
    try:
        store = EvidenceStore(args.evidence_root)
        reference = store.capture(args.request).reference()
        verified = verify_request(
            reference, store, args.checkout, args.expected_source_revision
        )
        if args.operation == "sign":
            result = sign_verified(
                verified,
                key_file=args.key_file,
                shadow_key_file=args.shadow_key_file,
                output_dir=args.output_dir,
            )
        else:
            result = {
                "verified": True,
                "source_revision": verified.request.source_revision,
                "candidate_manifest_digest": verified.candidate.canonical_digest,
                "product_active_run_completed": False,
            }
        print(json.dumps({"exit_code": 0, **result}, sort_keys=True))
        return 0
    except AdmissionError as error:
        print(json.dumps({"exit_code": 1, "error": error.code}))
        return 1
    except EvidenceError:
        print(json.dumps({"exit_code": 2, "error": "admission_evidence_unavailable"}))
        return 2
    except (OSError, RuntimeError):
        print(
            json.dumps({"exit_code": 2, "error": "admission_environment_unavailable"})
        )
        return 2
    except (ValueError, TypeError, KeyError, StopIteration):
        print(json.dumps({"exit_code": 1, "error": "admission_input_invalid"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
