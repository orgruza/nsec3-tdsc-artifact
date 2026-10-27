#!/usr/bin/env python3
"""Select the first complete measurement, otherwise the latest incomplete one."""

import argparse
import json
import sqlite3
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    source = Path(args.input)
    destination = Path(args.output)

    if source.resolve() == destination.resolve():
        raise SystemExit("Input and output must be different files.")

    destination.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="dnssec_dedup_") as temp_dir:
        database = Path(temp_dir) / "selection.sqlite"
        connection = sqlite3.connect(database)

        connection.execute("""
            CREATE TABLE selected (
                domain TEXT PRIMARY KEY,
                line_number INTEGER NOT NULL,
                complete INTEGER NOT NULL
            )
        """)

        total = 0
        invalid = 0

        with source.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    invalid += 1
                    continue

                domain = record["domain"]
                complete = int(record.get("complete") is True)
                total += 1

                connection.execute("""
                    INSERT INTO selected (domain, line_number, complete)
                    VALUES (?, ?, ?)
                    ON CONFLICT(domain) DO UPDATE SET
                        line_number = CASE
                            WHEN selected.complete = 0 THEN excluded.line_number
                            ELSE selected.line_number
                        END,
                        complete = MAX(selected.complete, excluded.complete)
                """, (domain, line_number, complete))

                if total % 200000 == 0:
                    connection.commit()
                    print(f"Indexed {total} records...", flush=True)

        connection.commit()

        unique, complete_count = connection.execute("""
            SELECT COUNT(*), SUM(complete) FROM selected
        """).fetchone()

        # Keep only selected line numbers in memory, not full DNS responses.
        selected_lines = {
            row[0] for row in connection.execute(
                "SELECT line_number FROM selected"
            )
        }

        written = 0

        with source.open("r", encoding="utf-8") as source_handle, \
             destination.open("w", encoding="utf-8") as output_handle:

            for line_number, line in enumerate(source_handle, start=1):
                if line_number in selected_lines:
                    output_handle.write(line)
                    written += 1

        connection.close()

    print("\n=== DEDUPLICATION RESULTS ===")
    print("Input records:", total)
    print("Unique domains:", unique)
    print("Complete domains:", complete_count)
    print("Incomplete domains:", unique - complete_count)
    print("Invalid input lines:", invalid)
    print("Output records:", written)
    print("Output file:", destination)

    if invalid or written != unique or unique != 1000000:
        raise SystemExit("ERROR: Deduplication validation failed.")

    print("PASS: Exactly one selected measurement per Tranco domain.")


if __name__ == "__main__":
    main()
