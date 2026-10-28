# NSEC3 in the Wild: Tranco Top-1M Measurement Artifact

## Overview

This artifact contains DNSSEC deployment and denial-of-existence
measurements for 1,000,000 domains from the Tranco Top-1M list.

It distinguishes DNSKEY publication, DS presence, RRSIG evidence,
observed NSEC/NSEC3 proofs, and resolver-validated denial proofs.

## Measurement

DNS queries were issued through a local Unbound resolver at
127.0.0.1:53 with DNSSEC validation enabled.

The measurement collected SOA, DS, DNSKEY, and conditional PTR
responses, including DNSSEC-related RRsets and AD flags.

## Dataset

- Input domains: 1,000,000
- Raw measurement records: 1,021,453
- Deduplicated domains: 1,000,000
- Complete measurements: 984,872
- Incomplete measurements: 15,128

Deduplication selects the first complete record per domain,
or the latest incomplete record if none is complete.

## Main Files

- input/domains.txt
- src/dns_probe.py
- src/measure.py
- src/deduplicate.py
- src/classify.py
- src/analyze_signing.py
- data/raw/tranco_1m_final.jsonl
- data/processed/tranco_1m_deduplicated.jsonl
- data/processed/tranco_1m_classification_final.csv
- results/

## Reproduce Classification

Run from the artifact root:

    /usr/bin/python3 -u src/classify.py --input data/processed/tranco_1m_deduplicated.jsonl --output data/processed/tranco_1m_classification_reproduced.csv

This operation does not issue new DNS queries.

## Results

| Measurement | Domains |
|---|---:|
| DNSKEY observed | 80,302 |
| RRSIG evidence observed | 80,105 |
| DS and DNSKEY observed | 56,513 |
| DNSKEY without observed DS | 23,789 |
| NSEC observed | 51,533 |
| NSEC3 observed | 28,136 |
| NSEC resolver-validated | 32,944 |
| NSEC3 resolver-validated | 23,372 |

These counts represent distinct properties and should not be added.

## Interpretation

DNSKEY observation indicates key publication, not necessarily
successful DNSSEC validation.

RRSIG evidence indicates a matching signer name and a signature
covering SOA, DNSKEY, NSEC, or NSEC3. The stored signatures are
not independently cryptographically verified by this classifier.

Resolver-validated denial classifications require the relevant
SOA and PTR responses to have AD=True.

An unclassified domain is not necessarily unsigned.

See DATA_DICTIONARY.md for detailed field definitions.

## Reproducibility

The original measurement data is preserved. Reproducing the
classification requires no new DNS measurements.

The measurement was conducted on October 24–26, 2026, using a
local DNSSEC-validating Unbound resolver. The exact Unbound
version used during the measurement was not recorded; version
1.19.2 was installed when the artifact was prepared, but this
does not establish the version used during measurement.
The original Tranco list identifier was not recorded. The exact
1,000,000-domain input list is included as `input/domains.txt`
to enable reproduction using the same domain set.

## Signed-domain classification

A domain is classified as signed (`signed_observed = true`) only
when both conditions hold:

1. A DNSKEY record was observed.
2. At least one RRSIG with a matching signer name was observed
   in the collected DNS responses.

The final measurement classifies 80,013 of the 1,000,000
domains as signed (8.00%).

The separate count of 80,105 domains with RRSIG evidence
does not require DNSKEY observation and must not be interpreted
as the signed-domain count.

Among the 80,013 signed domains, 51,533 were classified as
NSEC, 28,136 as NSEC3, and 344 had neither denial mechanism
observed.

## Complete measurement dataset

The complete Tranco measurement dataset is available as GitHub
Release assets:

https://github.com/orgruza/nsec3-tdsc-artifact/releases/tag/v1.0

Download:
- `tranco-measurement.tar.gz`
- `tranco-measurement.tar.gz.sha256`

Verify and extract:

```bash
sha256sum -c tranco-measurement.tar.gz.sha256
tar -xzf tranco-measurement.tar.gz

```

The archive extracts into `tranco-measurement/data/` and contains
the raw JSONL measurements, deduplicated JSONL measurements, and
the final classification CSV.
