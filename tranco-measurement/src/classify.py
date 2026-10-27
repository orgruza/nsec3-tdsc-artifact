#!/usr/bin/env python3
"""Conservative DNSSEC deployment and denial-of-existence classification."""

import argparse
import csv
import json
from pathlib import Path


def rrsets(observation, section):
    """Return structured RRsets from a DNS response section."""
    return observation.get(f"{section}_rrsets", [])


def records_of_type(observation, section, record_type, owner=None):
    """Select RRsets by type and optional owner name."""
    selected = [
        item for item in rrsets(observation, section)
        if item.get("type") == record_type and item.get("records")
    ]
    if owner is not None:
        selected = [
            item for item in selected
            if item.get("name", "").lower() == owner.lower()
        ]
    return selected


def successful(observation):
    """Identify successful DNS responses without transport errors."""
    return (
        observation.get("error") is None
        and observation.get("rcode") == "NOERROR"
    )



def signing_evidence_observed(record):
    """Detect zone-attributable RRSIG evidence, independent of DS."""
    owner = record["domain"].rstrip(".").lower() + "."
    observations = record.get("observations", {})

    for query_type in ("SOA", "DNSKEY", "PTR"):
        observation = observations.get(query_type, {})

        for section in ("answer_rrsets", "authority_rrsets"):
            for rrset in observation.get(section, []) or []:
                if rrset.get("type") != "RRSIG":
                    continue

                signers = {
                    str(signer).rstrip(".").lower() + "."
                    for signer in rrset.get("signers", [])
                }

                if owner not in signers:
                    continue

                for value in rrset.get("records", []):
                    covered_type = str(value).split()[0].upper()

                    if covered_type in ("SOA", "DNSKEY", "NSEC", "NSEC3"):
                        return True

    return False


def classify(record):
    """Classify observed and resolver-validated child-zone denial proofs."""
    domain = record["domain"]
    owner = domain.rstrip(".").lower() + "."
    observations = record.get("observations", {})

    soa = observations.get("SOA", {})
    ds = observations.get("DS", {})
    dnskey = observations.get("DNSKEY", {})
    ptr = observations.get("PTR", {})

    soa_at_apex = (
        successful(soa)
        and bool(records_of_type(soa, "answer", "SOA", owner))
    )
    apex_confirmed = soa_at_apex and soa.get("ad") is True

    ds_present = bool(records_of_type(ds, "answer", "DS", owner))
    dnskey_present = bool(
        records_of_type(dnskey, "answer", "DNSKEY", owner)
    )

    if successful(ds) and successful(dnskey):
        if ds_present and dnskey_present:
            deployment = "ds_and_dnskey_observed"
        elif dnskey_present:
            deployment = "dnskey_without_ds"
        elif not ds_present:
            deployment = "no_ds_observed"
        else:
            deployment = "unknown"
    else:
        deployment = "unknown"

    denial_observed = "unclassified"
    denial_validated = "unclassified"
    evidence = "none"

    if dnskey_present and soa_at_apex and successful(ptr):
        negative_ptr = not records_of_type(ptr, "answer", "PTR")

        if negative_ptr:
            authority = rrsets(ptr, "authority")

            def has_child_signed_proof(record_type):
                proof_owners = {
                    item.get("name", "").lower()
                    for item in authority
                    if item.get("type") == record_type
                    and item.get("records")
                }

                return any(
                    item.get("type") == "RRSIG"
                    and owner in [
                        signer.lower()
                        for signer in item.get("signers", [])
                    ]
                    and any(
                        str(value).split()[0].upper() == record_type
                        for value in item.get("records", [])
                    )
                    and item.get("name", "").lower() in proof_owners
                    for item in authority
                )

            nsec = has_child_signed_proof("NSEC")
            nsec3 = has_child_signed_proof("NSEC3")

            if nsec != nsec3:
                denial_observed = "NSEC" if nsec else "NSEC3"
                evidence = "child_zone_proof_observed"

                if ptr.get("ad") is True and apex_confirmed:
                    denial_validated = denial_observed
                    evidence = "validated_child_zone_proof"

            elif nsec and nsec3:
                evidence = "conflicting_proof_types"

    return {
        "domain": domain,
        "deployment": deployment,
        "apex_confirmed": apex_confirmed,
        "denial": denial_validated,
        "denial_observed": denial_observed,
        "denial_validated": denial_validated,
        "evidence": evidence,
        "ds_present": ds_present,
        "dnskey_present": dnskey_present,
        "signing_evidence_observed": signing_evidence_observed(record),
        "signed_observed": dnskey_present and signing_evidence_observed(record),
        "ptr_ad": ptr.get("ad"),
        "measurement_complete": record.get("complete", False),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input", default="data/raw/measurements.jsonl"
    )
    parser.add_argument(
        "--output", default="data/processed/classification.csv"
    )
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "domain", "deployment", "apex_confirmed",
        "denial", "denial_observed", "denial_validated", "evidence",
        "ds_present", "dnskey_present", "signing_evidence_observed", "signed_observed", "ptr_ad",
        "measurement_complete",
    ]

    count = 0
    invalid = 0

    with open(args.input, encoding="utf-8") as source_handle, \
         output.open("w", newline="", encoding="utf-8") as output_handle:

        writer = csv.DictWriter(output_handle, fieldnames=fields)
        writer.writeheader()

        for line in source_handle:
            try:
                record = json.loads(line)
                if not isinstance(record, dict) or "domain" not in record:
                    invalid += 1
                    continue
            except (json.JSONDecodeError, TypeError):
                invalid += 1
                continue

            writer.writerow(classify(record))
            count += 1

            if count % 100000 == 0:
                print(f"Classified {count} domains...", flush=True)

    print(f"Classified domains: {count}")
    print(f"Invalid input records: {invalid}")
    print(f"Output: {output}")


if __name__ == "__main__":
    main()
