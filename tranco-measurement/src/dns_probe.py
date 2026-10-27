#!/usr/bin/env python3
"""DNS measurement primitives for the reproducible deployment scan."""

import time

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype


RESOLVER = "127.0.0.1"
TIMEOUT = 2.0



def serialize_rrsets(rrsets):
    """Serialize DNS RRsets with explicit type and signer metadata."""
    serialized = []

    for rrset in rrsets:
        record_type = dns.rdatatype.to_text(rrset.rdtype)

        signers = []
        if record_type == "RRSIG":
            signers = sorted({
                rdata.signer.to_text()
                for rdata in rrset
            })

        serialized.append({
            "name": rrset.name.to_text(),
            "type": record_type,
            "ttl": rrset.ttl,
            "records": [rdata.to_text() for rdata in rrset],
            "signers": signers,
        })

    return serialized


def query_dns(domain, record_type, timeout=TIMEOUT):
    """Query a validating recursive resolver and preserve response details."""
    request = dns.message.make_query(
        domain,
        record_type,
        want_dnssec=True,
    )

    started = time.monotonic()

    try:
        response = dns.query.udp(
            request,
            RESOLVER,
            timeout=timeout,
        )

        transport = "udp"

        if response.flags & dns.flags.TC:
            response = dns.query.tcp(
                request,
                RESOLVER,
                timeout=timeout,
            )
            transport = "tcp"

        return {
            "domain": domain,
            "query_type": record_type,
            "rcode": dns.rcode.to_text(response.rcode()),
            "ad": bool(response.flags & dns.flags.AD),
            "cd": bool(response.flags & dns.flags.CD),
            "transport": transport,
            "answer": [rrset.to_text() for rrset in response.answer],
            "answer_rrsets": serialize_rrsets(response.answer),
            "authority": [rrset.to_text() for rrset in response.authority],
            "authority_rrsets": serialize_rrsets(response.authority),
            "elapsed_ms": round(
                (time.monotonic() - started) * 1000, 2
            ),
            "error": None,
        }

    except Exception as exc:
        return {
            "domain": domain,
            "query_type": record_type,
            "rcode": None,
            "ad": None,
            "cd": None,
            "transport": None,
            "answer": [],
            "answer_rrsets": [],
            "authority": [],
            "authority_rrsets": [],
            "elapsed_ms": round(
                (time.monotonic() - started) * 1000, 2
            ),
            "error": type(exc).__name__,
        }
