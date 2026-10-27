#!/usr/bin/env python3
"""Audit DNSSEC signing evidence independently of DS presence."""

import argparse
import csv
import json
from collections import Counter


def normalize(name):
    return str(name).rstrip(".").lower() + "."


def signature_evidence(record):
    """Return RRSIG evidence attributable to the measured zone."""
    owner = normalize(record["domain"])
    observations = record.get("observations", {})

    evidence = set()

    for query_type in ("SOA", "DNSKEY", "PTR"):
        observation = observations.get(query_type, {})

        for section in ("answer_rrsets", "authority_rrsets"):
            for rrset in observation.get(section, []) or []:
                if rrset.get("type") != "RRSIG":
                    continue

                signers = {
                    normalize(signer)
                    for signer in rrset.get("signers", [])
                }

                if owner not in signers:
                    continue

                for value in rrset.get("records", []):
                    covered_type = str(value).split()[0].upper()

                    if covered_type in ("SOA", "DNSKEY", "NSEC", "NSEC3"):
                        evidence.add(covered_type)

    return evidence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="data/processed/tranco_1m_deduplicated.jsonl",
    )
    parser.add_argument(
        "--classification",
        default="data/processed/tranco_1m_classification.csv",
    )
    args = parser.parse_args()

    counts = Counter()
    examples = {}
    total = 0

    with open(args.input, encoding="utf-8") as raw_file, \
         open(args.classification, newline="", encoding="utf-8") as csv_file:

        classifications = csv.DictReader(csv_file)

        for line, category in zip(raw_file, classifications):
            record = json.loads(line)
            total += 1

            domain = record["domain"]

            if domain != category["domain"]:
                raise RuntimeError(
                    f"Domain mismatch at row {total}: "
                    f"{domain} != {category['domain']}"
                )

            deployment = category["deployment"]
            evidence = signature_evidence(record)
            dnskey_present = category["dnskey_present"].lower() == "true"
            signed = dnskey_present and bool(evidence)

            if signed:
                counts[(deployment, "signed")] += 1

            counts[(deployment, "total")] += 1

            if evidence:
                counts[(deployment, "signed_evidence")] += 1
                examples.setdefault(deployment, domain)
            else:
                counts[(deployment, "no_evidence")] += 1

            for covered_type in evidence:
                counts[(deployment, covered_type)] += 1

            if total % 100000 == 0:
                print(f"Processed {total} domains...", flush=True)

        if raw_file.readline():
            raise RuntimeError("JSONL contains additional records.")

        if next(classifications, None) is not None:
            raise RuntimeError("CSV contains additional records.")

    categories = [
        "signed_observed",
        "dnskey_without_ds",
        "no_ds_observed",
        "unknown",
    ]

    print("\n=== SIGNATURE EVIDENCE BY DEPLOYMENT ===")
    print(
        f"{'Deployment':<23}"
        f"{'Total':>10}"
        f"{'RRSIG evidence':>17}"
        f"{'No evidence':>15}"
    )

    for dep in categories:
        print(
            f"{dep:<23}"
            f"{counts[(dep, 'total')]:>10}"
            f"{counts[(dep, 'signed_evidence')]:>17}"
            f"{counts[(dep, 'no_evidence')]:>15}"
        )

    print("\n=== RRSIG COVERED TYPES ===")
    print(
        f"{'Deployment':<23}"
        f"{'SOA':>10}"
        f"{'DNSKEY':>10}"
        f"{'NSEC':>10}"
        f"{'NSEC3':>10}"
    )

    for dep in categories:
        print(
            f"{dep:<23}"
            f"{counts[(dep, 'SOA')]:>10}"
            f"{counts[(dep, 'DNSKEY')]:>10}"
            f"{counts[(dep, 'NSEC')]:>10}"
            f"{counts[(dep, 'NSEC3')]:>10}"
        )

    print("\n=== EXAMPLE DOMAINS ===")
    for dep in categories:
        print(f"{dep}: {examples.get(dep, 'none')}")

    print("\nTotal domains:", total)
    print(
        "Signed domains (DNSKEY + RRSIG):",
        sum(counts[(dep, "signed")] for dep in categories),
    )
    print(
        "Domains with RRSIG evidence:",
        sum(counts[(dep, "signed_evidence")] for dep in categories),
    )


if __name__ == "__main__":
    main()
