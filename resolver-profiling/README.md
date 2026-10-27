# Resolver Profiling Data

This directory documents the profiling measurements used in
the TDSC study "Same Attack, Different Failures: Architecture
Shapes NSEC3 Mitigation Effectiveness".

## Dataset

The complete profiling dataset is distributed as a GitHub
Release asset:

- resolver-profiling.tar.gz
- resolver-profiling.tar.gz.sha256

The archive contains the original `profiled-data/` directory,
including the `measurements/` subdirectory.

## Experiment structure

Each experiment directory is named according to its duration,
attack request rate, NSEC3 iteration count, benign request
rate, and timestamp.

Individual resolver directories contain measurement files
such as:

- cpu-high.log
- cpu-low.log
- net.log
- benign.log
- nsec3-attacker.log
- test.json

## Extracting the dataset

Download the archive and its SHA-256 checksum file from the
GitHub Releases page.

Verify the archive:

    sha256sum -c resolver-profiling.tar.gz.sha256

Extract it:

    tar -xzf resolver-profiling.tar.gz

The extracted files will be available under:

    profiled-data/measurements/
