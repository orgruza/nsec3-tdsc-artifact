# Data Dictionary

This document describes the classification fields in
data/processed/tranco_1m_classification_final.csv.

## domain

The measured domain name.

## deployment

Observed DS/DNSKEY configuration:

- ds_and_dnskey_observed: Both DS and DNSKEY observed.
- dnskey_without_ds: DNSKEY observed without DS.
- no_ds_observed: Neither DS nor DNSKEY observed in the
  corresponding successful queries.
- unknown: Insufficient observations for classification.

These labels do not independently establish DNSSEC validation.

## ds_present

Boolean indicating whether a DS record was observed.

## dnskey_present

Boolean indicating whether a DNSKEY record was observed.

This is the operational indicator for DNSSEC key publication.

## signing_evidence_observed

Boolean indicating that at least one RRSIG was observed with:

- A signer name matching the measured domain.
- A covered type of SOA, DNSKEY, NSEC, or NSEC3.
- Presence in the stored SOA, DNSKEY, or PTR response RRsets.

This does not constitute independent cryptographic verification.

## apex_confirmed

Boolean indicating an SOA record at the measured apex and
AD=True for the corresponding SOA response.

## denial_observed

Possible values: NSEC, NSEC3, unclassified.

Requires DNSKEY observation, an SOA record at the apex,
a negative PTR response, and a corresponding child-zone
NSEC/NSEC3 RRset with RRSIG evidence.

## denial_validated

Possible values: NSEC, NSEC3, unclassified.

Requires an observed denial proof and AD=True for both
the SOA and PTR responses.

Validation is attributed to the configured Unbound resolver.

## denial

Backward-compatible alias for denial_validated.

## evidence

Possible values:

- none
- child_zone_proof_observed
- validated_child_zone_proof
- conflicting_proof_types

## ptr_ad

Authenticated Data flag of the PTR response.

## measurement_complete

Boolean indicating whether the selected measurement
was marked complete by the measurement pipeline.

## Limitations

- Missing DS does not imply an unsigned zone.
- DNSKEY alone does not prove that DNS data is signed.
- RRSIG observation alone does not prove successful validation.
- AD-based validation depends on resolver configuration.
- Unclassified does not mean unsigned.

## signed_observed

Boolean indicating whether both of the following were observed:

- A DNSKEY record (`dnskey_present = true`).
- RRSIG evidence with a matching signer name
  (`signing_evidence_observed = true`).

This field defines the signed-domain population used in the
paper. It is distinct from `signing_evidence_observed`, which
records RRSIG evidence independently of DNSKEY observation.
