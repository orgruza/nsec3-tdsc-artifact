#!/usr/bin/env python3

import os
import re
import json
import sys
import math

import matplotlib
import numpy as np
from colorspacious import *

NAMES = {
    "bind9-16-1": "BIND 9.16.1",
    "bind9-18-24": "BIND 9.18.24",
    "bind9-20-13": "BIND 9.20.13",
    "knot-5-6-0": "Knot 5.6.0",
    "knot-5-7-3": "Knot 5.7.3",
    "knot-6-1-0": "Knot 6.1.0",
    "powerdns-4-8-2": "PowerDNS 4.8.2",
    "powerdns-5-0-5": "PowerDNS 5.0.5",
    "powerdns-5-2-4": "PowerDNS 5.2.4",
    "unbound-1-17-1": "Unbound 1.17.1",
    "unbound-1-24-0": "Unbound 1.24.0",
}

measurements = "measurements"
test_prefix = "1min-8x"
test_suffix = "-benign-"

def find_subfolders_with_metadata(folder=measurements, prefix=test_prefix, suffix=test_suffix):
    """
    Find subfolders in 'folder' matching the naming pattern and extract substring info.

    Args:
        folder (str): Path to main folder.
        prefix (str): Prefix in folder name.
        suffix (str): Suffix in folder name.

    Returns:
        dict: {subfolder_name: {"rps": int, "iter": int}, ...}
    """
    results = {}
    # Regex to match pattern: prefix + substring + suffix + timestamp
    # substring: (\d+)rps-(\d+)iter
    pattern = re.compile(
        f"^{re.escape(prefix)}([.\\d]+)rps\\-(\\d+)iter{re.escape(suffix)}(.+)$"
    )

    for entry in os.listdir(folder):
        entry_path = os.path.join(folder, entry)
        if os.path.isdir(entry_path):
            m = pattern.match(entry)
            if m:
                rps, iteration = float(m.group(1)), int(m.group(2))
                results[entry] = {"rps": rps, "iter": iteration}
    return results


def reorder_by_iter_and_rps(input_dict):
    """
    Reorder a dict of subfolder metadata to {iter: {rps: [subfolder, ...], ...}, ...}

    Args:
        input_dict (dict): {"subfolder": {"rps": int, "iter": int}, ...}

    Returns:
        dict: {iter: {rps: [subfolder, ...], ...}, ...}
    """
    result = {}
    for subfolder, meta in input_dict.items():
        iter_val = meta["iter"]
        rps_val = meta["rps"]
        if iter_val not in result:
            result[iter_val] = {}
        if rps_val not in result[iter_val]:
            result[iter_val][rps_val] = []
        result[iter_val][rps_val].append(subfolder)
    return result


def aggregate_query_statuses(folder, monitor):
    """
    Aggregate status counts from query monitor logs in all resolvers for this measurement folder.
    Args:
        folder (str): Path to measurement folder.
        monitor (str): Monitor name (filename prefix).

    Returns:
        dict: {subfolder: {"noerror": X, "servfail": X, "timeout": X, "error": X, "nxdomain": X, "refused": X}, ...}
    """
    status_enum = {
        0: "noerror",
        1: "servfail",
        2: "timeout",
        3: "error",
        4: "nxdomain",
        5: "refused"
    }
    result = {}

    for subfolder in os.listdir(folder):
        path = os.path.join(folder, subfolder)
        if os.path.isdir(path):
            log_path = os.path.join(path, monitor + ".log")
            counts = {name: 0 for name in status_enum.values()}
            if os.path.isfile(log_path):
                with open(log_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line == "null":
                            continue
                        try:
                            record = json.loads(line)
                            status = record.get("status")
                            if status in status_enum:
                                counts[status_enum[status]] += 1
                        except Exception:
                            continue
                result[subfolder] = counts
            else:
                print(f"could not find {monitor}.log in {folder}/{subfolder}", file=sys.stderr)
    return result


def aggregate_confidence(
    grouped_tests, base_path, monitor, total_points=5999, z_value=1.96
):
    """
    For each (iter, rps, implementation), computes average timeout and servfail rates
    across test runs and a 95% confidence interval (normal approx std error).

    Args:
        grouped_tests (dict): {iter: {rps: [test_folder, ...], ...}, ...}
        base_path (str): Path containing test_folder directories.
        monitor (str): Prefix for log file (e.g., "resolver")
        total_points (int): Number of rows per implementation (default 5999).
        z_value (float): Z value for confidence interval (default 1.96 for 95%).

    Returns:
        dict: {iter: {rps: {implementation:
              {"timeout_rate": mean, "timeout_conf": conf,
               "servfail_rate": mean, "servfail_conf": conf}}}}
    """
    results = {}
    for iter_val, rps_group in grouped_tests.items():
        results[iter_val] = {}
        for rps_val, test_folders in rps_group.items():
            impl_stats = {}  # {impl: [list of {"timeout": int, "servfail": int}]}
            for test_folder in test_folders:
                test_folder_path = os.path.join(base_path, test_folder)
                if not os.path.isdir(test_folder_path):
                    continue
                for impl in os.listdir(test_folder_path):
                    impl_path = os.path.join(test_folder_path, impl)
                    log_file = os.path.join(impl_path, f"{monitor}.log")
                    if not os.path.isfile(log_file):
                        continue
                    timeout_count = 0
                    servfail_count = 0
                    with open(log_file) as f:
                        for line in f:
                            line = line.strip()
                            if not line or line == "null":
                                continue
                            try:
                                rec = json.loads(line)
                                status = rec.get("status")
                                if status == 1:
                                    servfail_count += 1
                                elif status == 2:
                                    timeout_count += 1
                            except Exception:
                                continue
                    impl_stats.setdefault(impl, []).append({
                        "timeout": timeout_count / total_points,
                        "servfail": servfail_count / total_points
                    })
            # Compute statistics per implementation
            results[iter_val][rps_val] = {}
            for impl, runs in impl_stats.items():
                n = len(runs)
                if n == 0:
                    continue
                timeout_rates = [run["timeout"] for run in runs]
                servfail_rates = [run["servfail"] for run in runs]
                timeout_mean = sum(timeout_rates) / n
                servfail_mean = sum(servfail_rates) / n
                timeout_stderr = (
                    (sum((x - timeout_mean) ** 2 for x in timeout_rates) / (n - 1)) ** 0.5 / n ** 0.5
                    if n > 1 else 0
                )
                servfail_stderr = (
                    (sum((x - servfail_mean) ** 2 for x in servfail_rates) / (n - 1)) ** 0.5 / n ** 0.5
                    if n > 1 else 0
                )
                results[iter_val][rps_val][impl] = {
                    "timeout_rate": timeout_mean,
                    "timeout_conf": z_value * timeout_stderr,
                    "servfail_rate": servfail_mean,
                    "servfail_conf": z_value * servfail_stderr
                }
    return results


def summarize_confidence(table):
    """
    Summarize global confidence indicators from your table.

    Args:
        table (dict): Nested aggregate result structure as generated by aggregate_confidence.

    Returns:
        dict: Summary of mean, median, and coefficient of variation for timeout and servfail confidence.
    """
    timeout_conf_list = []
    servfail_conf_list = []

    for iter_val in table.values():
        for rps_val in iter_val.values():
            for impl_stats in rps_val.values():
                timeout_conf_list.append(impl_stats.get('timeout_conf', 0))
                servfail_conf_list.append(impl_stats.get('servfail_conf', 0))

    timeout_conf_arr = np.array(timeout_conf_list)
    servfail_conf_arr = np.array(servfail_conf_list)

    summary = {
        "timeout_confidence": {
            "mean": float(timeout_conf_arr.mean()),
            "median": float(np.median(timeout_conf_arr)),
            "cv": float(timeout_conf_arr.std() / timeout_conf_arr.mean()) if timeout_conf_arr.mean() else float('nan')
        },
        "servfail_confidence": {
            "mean": float(servfail_conf_arr.mean()),
            "median": float(np.median(servfail_conf_arr)),
            "cv": float(servfail_conf_arr.std() / servfail_conf_arr.mean()) if servfail_conf_arr.mean() else float('nan')
        }
    }
    return summary


def find_confidence_outliers(table):
    import numpy as np

    timeout_conf_tuples = []
    servfail_conf_tuples = []

    # Collect (value, (iter, rps, impl))
    for iter_val, rps_dict in table.items():
        for rps_val, impl_dict in rps_dict.items():
            for impl, stats in impl_dict.items():
                tconf = stats.get('timeout_conf', 0)
                sconf = stats.get('servfail_conf', 0)
                timeout_conf_tuples.append((tconf, (iter_val, rps_val, impl)))
                servfail_conf_tuples.append((sconf, (iter_val, rps_val, impl)))

    # Calculate IQR thresholds for timeout_conf
    tconf_values = np.array([x[0] for x in timeout_conf_tuples])
    Q1_t, Q3_t = np.percentile(tconf_values, [25, 75])
    IQR_t = Q3_t - Q1_t
    threshold_t = Q3_t + 1.5 * IQR_t

    # And servfail_conf
    sconf_values = np.array([x[0] for x in servfail_conf_tuples])
    Q1_s, Q3_s = np.percentile(sconf_values, [25, 75])
    IQR_s = Q3_s - Q1_s
    threshold_s = Q3_s + 1.5 * IQR_s

    timeout_outliers = [(v, triple) for v, triple in timeout_conf_tuples if v > threshold_t]
    servfail_outliers = [(v, triple) for v, triple in servfail_conf_tuples if v > threshold_s]

    return {
        "timeout_outlier_threshold": threshold_t,
        "servfail_outlier_threshold": threshold_s,
        "timeout_outliers": timeout_outliers,
        "servfail_outliers": servfail_outliers,
    }


# Example use:
# summary = summarize_confidence(your_table)
# print(summary)


tests = find_subfolders_with_metadata()
reordered = reorder_by_iter_and_rps(tests)
print(reordered)

aggregate = aggregate_confidence(reordered, measurements, 'benign')
print(aggregate)

summary = summarize_confidence(aggregate)
print(summary)

outliers = find_confidence_outliers(aggregate)
print("Timeout outliers (above %.5f):" % outliers['timeout_outlier_threshold'])

for val, (it, rp, impl) in sorted(
    outliers['timeout_outliers'],
    key=lambda x: x[0],
    reverse=True
):
    print(f'  iter={it}, rps={rp}, impl="{impl}": timeout_conf={val:.5f}')

print("\nServfail outliers (above %.5f):" % outliers['servfail_outlier_threshold'])

for val, (it, rp, impl) in sorted(
    outliers['servfail_outliers'],
    key=lambda x: x[0],
    reverse=True
):
    print(f'  iter={it}, rps={rp}, impl="{impl}": servfail_conf={val:.5f}')

# plotting


def perceptual_colormap(start_hex, end_hex, N=256):
    # RGB -> CAM02-UCS
    start_rgb = np.array(matplotlib.colors.to_rgb(start_hex))
    end_rgb = np.array(matplotlib.colors.to_rgb(end_hex))

    start_lab = cspace_convert(start_rgb, "sRGB1", "CAM02-UCS")
    end_lab   = cspace_convert(end_rgb, "sRGB1", "CAM02-UCS")

    # Linear interpolation in CAM02-UCS
    interp = np.linspace(0,1,N)[:,None]
    colors_lab = start_lab + (end_lab - start_lab) * interp

    # Convert back to RGB
    colors_rgb = cspace_convert(colors_lab, "CAM02-UCS", "sRGB1")
    colors_rgb = np.clip(colors_rgb, 0, 1)

    return matplotlib.colors.ListedColormap(colors_rgb)

cmaps = {
        "DarkReds": perceptual_colormap("#FFFFFF", "#600117"),
        "DarkBlues": perceptual_colormap("#FFFFFF", "#08326F"),
        "Reds": perceptual_colormap("#FFFFFF", "#B01217"),
        "Blues": perceptual_colormap("#FFFFFF", "#1033AF"),
}

cmap1="Blues"
cmap2="Reds"

if not cmap1 is None:
    if cmap1 in cmaps:
        cmap1 = cmaps[cmap1]
    else:
        cmap1 = matplotlib.colormaps[cmap1]
if not cmap2 is None:
    if cmap2 in cmaps:
        cmap2 = cmaps[cmap2]
    else:
        cmap2 = matplotlib.colormaps[cmap2]

def colored_cell(value, cmap):
    percent = int(round(value*100,0))
    if cmap is None:
        return f"{percent}"
    rgba = cmap(value)
    hex_color = matplotlib.colors.to_hex(rgba)[1:].upper() # remove leading '#'

    # luminance for contrast text color
    r, g, b = rgba[:3]
    luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b
    text_color = "black" if luminance > 0.5 else "white"

    latex = (
        rf"\cellcolor[HTML]{{{hex_color}}}"
        rf"\textcolor{{{text_color}}}{{{percent}}}"
    )

    return latex

#exit()

for iter_val, rps_vals in aggregate.items():
    print('\n'*8)
    print(f'% {iter_val}')
    for resolver in NAMES.keys():
        line = ""

        rps_keys = sorted(list(rps_vals.keys()))

        for rps in rps_keys:
            if rps == 0:
                continue
            entry = rps_vals[rps][resolver]
            to_rate = entry['timeout_rate']
            err_rate = entry['servfail_rate']

            err_percent = colored_cell(err_rate, cmap1)
            line += f" & {err_percent}"
            to_percent = colored_cell(to_rate, cmap2)
            line += f" & {to_percent}"

        print(f"{NAMES[resolver]}{line} \\\\")




