#!/usr/bin/env python3
"""Bounded, resumable DNSSEC deployment measurement."""

import argparse
import concurrent.futures
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.rdatatype

from dns_probe import query_dns


REQUIRED_TYPES = ("SOA", "DS", "DNSKEY")
TRANSIENT_RCODES = {"SERVFAIL", "REFUSED"}


def has_record(observation, record_type):
    """Check the structured answer for the requested DNS record type."""
    if observation.get("rcode") != "NOERROR":
        return False

    return any(
        rrset.get("type") == record_type
        and bool(rrset.get("records"))
        for rrset in observation.get("answer_rrsets", [])
    )


def query_with_retries(domain, record_type, retries, timeout):
    """Retry transport failures and transient DNS errors."""
    attempts = []

    for _ in range(retries + 1):
        result = query_dns(domain, record_type, timeout=timeout)
        attempts.append(result)

        if result["error"] is None and result["rcode"] not in TRANSIENT_RCODES:
            break

    return {
        **attempts[-1],
        "attempts": attempts,
    }


def measure_domain(domain, retries=2, timeout=3.0):
    """Collect deployment observations and conditional PTR evidence."""
    observations = {}

    for record_type in REQUIRED_TYPES:
        observations[record_type] = query_with_retries(
            domain, record_type, retries, timeout
        )

    if has_record(observations["DNSKEY"], "DNSKEY"):
        observations["PTR"] = query_with_retries(
            domain, "PTR", retries, timeout
        )

    required = list(REQUIRED_TYPES)
    if "PTR" in observations:
        required.append("PTR")

    complete = all(
        observations[record_type]["error"] is None
        and observations[record_type]["rcode"] not in TRANSIENT_RCODES
        for record_type in required
    )

    return {
        "domain": domain,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "complete": complete,
        "observations": observations,
    }



def repair_jsonl_tail(path):
    """Remove an invalid or incomplete final JSONL record."""
    import json

    path = Path(path)

    if not path.exists() or path.stat().st_size == 0:
        return

    with path.open("rb+") as handle:
        data = handle.read()
        lines = data.splitlines(keepends=True)

        if not lines:
            return

        last = lines[-1]

        try:
            json.loads(last)
        except (json.JSONDecodeError, UnicodeDecodeError):
            handle.truncate(len(data) - len(last))
            print("Removed invalid trailing JSONL record.")
            return

        if not last.endswith(bytes([10])):
            handle.seek(0, 2)
            handle.write(bytes([10]))
            print("Restored missing JSONL newline.")



def load_completed(path):
    """Return domains whose latest stored result is complete."""
    latest = {}

    if not path.exists():
        return set()

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
                latest[record["domain"]] = record.get("complete", False)
            except (json.JSONDecodeError, KeyError, TypeError):
                continue

    return {
        domain for domain, complete in latest.items() if complete
    }


def run_measurement(domains, output_path, workers, retries, timeout):
    """Execute a bounded number of concurrent domain measurements."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    repair_jsonl_tail(output_path)
    completed = load_completed(output_path)
    pending = [domain for domain in domains if domain not in completed]

    print(
        f"Input domains: {len(domains)}; "
        f"completed: {len(domains) - len(pending)}; "
        f"remaining: {len(pending)}",
        flush=True,
    )

    started = time.monotonic()
    processed = 0
    domain_iterator = iter(pending)
    max_inflight = workers * 4

    with output_path.open("a", encoding="utf-8") as output:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers
        ) as executor:

            futures = {}

            def submit_next():
                try:
                    domain = next(domain_iterator)
                except StopIteration:
                    return False

                future = executor.submit(
                    measure_domain, domain, retries, timeout
                )
                futures[future] = domain
                return True

            for _ in range(min(max_inflight, len(pending))):
                submit_next()

            while futures:
                done, _ = concurrent.futures.wait(
                    futures,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )

                for future in done:
                    domain = futures.pop(future)

                    try:
                        record = future.result()
                    except Exception as exc:
                        record = {
                            "domain": domain,
                            "timestamp_utc": datetime.now(
                                timezone.utc
                            ).isoformat(),
                            "complete": False,
                            "observations": {},
                            "error": repr(exc),
                        }

                    output.write(json.dumps(record) + "\n")
                    processed += 1

                    submit_next()

                    if processed % 1000 == 0:
                        output.flush()
                        elapsed = time.monotonic() - started
                        print(
                            f"Processed: {processed}/{len(pending)}; "
                            f"throughput: {processed / elapsed:.1f} domains/s",
                            flush=True,
                        )

            output.flush()

    print("Measurement run finished.", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="input/domains.txt")
    parser.add_argument(
        "--output", default="data/raw/measurements.jsonl"
    )
    parser.add_argument("--workers", type=int, default=50)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    if args.workers < 1 or args.retries < 0 or args.timeout <= 0:
        parser.error("Invalid workers, retries, or timeout value.")

    with open(args.input, encoding="utf-8") as handle:
        domains = [line.strip() for line in handle if line.strip()]

    if args.limit:
        domains = domains[:args.limit]

    run_measurement(
        domains,
        args.output,
        args.workers,
        args.retries,
        args.timeout,
    )


if __name__ == "__main__":
    main()
