import csv
import json
import re
from collections import Counter

BASE = "data/processed/"
classified = set()

with open(BASE + "tranco_1m_classification_final.csv", newline="") as f:
    for row in csv.DictReader(f):
        if row["denial_observed"] == "NSEC3":
            classified.add(row["domain"].rstrip(".").lower())

iterations = Counter()
salt_lengths = Counter()
missing = []
conflicts = []

def normalize(name):
    return str(name).rstrip(".").lower()

def parse_nsec3(rdata):
    fields = rdata.split()
    if len(fields) < 5:
        return None

    try:
        algorithm = int(fields[0])
        flags = int(fields[1])
        iteration = int(fields[2])
    except ValueError:
        return None

    salt = fields[3]
    if salt == "-":
        salt_length = 0
    elif re.fullmatch(r"(?:[0-9a-fA-F]{2})+", salt):
        salt_length = len(salt) // 2
    else:
        return None

    return iteration, salt_length

with open(BASE + "tranco_1m_deduplicated.jsonl") as f:
    for line in f:
        record = json.loads(line)
        domain = normalize(record["domain"])
        if domain not in classified:
            continue

        ptr = record.get("observations", {}).get("PTR", {})
        rrsets = ptr.get("authority_rrsets", [])

        # Match RRSIG(NSEC3) to its NSEC3 RRset by owner and signer.
        signed_owners = set()
        for rrset in rrsets:
            if rrset.get("type") != "RRSIG":
                continue

            owner = normalize(rrset.get("name", ""))
            for rdata in rrset.get("records", []):
                fields = rdata.split()
                if (
                    fields
                    and fields[0].upper() == "NSEC3"
                    and len(fields) >= 9
                    and normalize(fields[7]) == domain
                ):
                    signed_owners.add(owner)

        found = set()
        for rrset in rrsets:
            if rrset.get("type") != "NSEC3":
                continue
            if normalize(rrset.get("name", "")) not in signed_owners:
                continue

            for rdata in rrset.get("records", []):
                parsed = parse_nsec3(rdata)
                if parsed is not None:
                    found.add(parsed)

        if len(found) == 1:
            iteration, salt_length = next(iter(found))
            iterations[iteration] += 1
            salt_lengths[salt_length] += 1
        elif not found:
            missing.append(domain)
        else:
            conflicts.append((domain, sorted(found)))

total = sum(iterations.values())

print("NSEC3-classified domains:", len(classified))
print("Domains with extracted parameters:", total)
print("Missing:", len(missing))
print("Conflicting parameters:", len(conflicts))

if not total:
    raise SystemExit("No parameters extracted; inspect the data format.")

print("\nIteration counts (top 20):")
for value, count in iterations.most_common(20):
    print(f"  I={value}: {count} ({count / total * 100:.2f}%)")

print("\nSalt lengths in bytes:")
for value, count in sorted(salt_lengths.items()):
    print(f"  s={value}: {count} ({count / total * 100:.2f}%)")

print("\nIteration thresholds:")
for threshold in (1, 10, 50, 100, 150, 500):
    count = sum(n for i, n in iterations.items() if i >= threshold)
    print(f"  I >= {threshold}: {count} ({count / total * 100:.2f}%)")

print("\nMaximum iteration count:", max(iterations))
print("Maximum salt length:", max(salt_lengths))

if missing:
    print("\nFirst missing domains:", missing[:10])
if conflicts:
    print("First conflicts:", conflicts[:10])

# Figure 3: Share of zones meeting/exceeding each parameter value.
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path

def share_at_least(counts, x):
    return sum(n for value, n in counts.items() if value >= x) / total

x = list(range(141))
salt_share = [share_at_least(salt_lengths, v) for v in x]
iteration_share = [share_at_least(iterations, v) for v in x]

fig, ax = plt.subplots(figsize=(7, 2.7))

ax.plot(x, salt_share, label="Salt Length")
ax.plot(x, iteration_share, label="Iteration Count")

ax.set_xlim(0, 140)
ax.set_ylim(0, 1)
ax.set_xticks(range(0, 141, 20))
ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])

ax.set_xlabel("Salt Length / Iteration Count")
ax.set_ylabel("Share of Zones")
ax.grid(True, alpha=0.3)
ax.legend(loc="upper right")

fig.tight_layout()

out = Path("results")
out.mkdir(exist_ok=True)

fig.savefig(out / "nsec3_parameter_distribution_final.pdf")
fig.savefig(out / "nsec3_parameter_distribution_final.png", dpi=300)
plt.close(fig)

print("\nFigure 3 created:")
print(" results/nsec3_parameter_distribution_final.pdf")
print(" results/nsec3_parameter_distribution_final.png")
