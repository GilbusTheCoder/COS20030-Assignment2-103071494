#COS20030 Section 12: two YARA directory scans, offline heuristic search.
from __future__ import annotations

import argparse
import csv
import itertools
import random
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_DATASET = Path(r"C:\Users\student\MalwareSample\lab10\lab10\lab10_dataset")
DEFAULT_YARA = Path(r"C:\Users\student\Tools\yara64.exe")
BASELINE = "Advanced_PE_HeuristicV1"
PE_RULE = "P_IsPE"

# Seven PE-attribute categories from the existing coursework rule. Alternative
# thresholds are experiments, NOT thresholds claimed as sourced from the paper.
GROUPS = {
    "Timestamp": {
        "H_Time_V1": "(pe.timestamp < 694224000 or pe.timestamp > 1798761600)",
        "H_Time_Pre1992": "pe.timestamp < 694224000",
        "H_Time_Pre2000": "pe.timestamp < 946684800",
        "H_Time_Zero": "pe.timestamp == 0",
        "H_Time_Future2027": "pe.timestamp > 1798761600",
        "H_Time_VeryFuture2030": "pe.timestamp > 1893456000",
    },
    "SectionCount": {
        "H_Sections_GT6": "pe.number_of_sections > 6",
        "H_Sections_GT8": "pe.number_of_sections > 8",
        "H_Sections_GT10": "pe.number_of_sections > 10",
    },
    "SymbolTable": {
        "H_Symbol_OutOfBounds": "(pe.pointer_to_symbol_table > 0 and pe.pointer_to_symbol_table >= filesize)",
    },
    "CodeSize": {"H_Code_OverFile": "pe.size_of_code > filesize"},
    "UninitializedData": {"H_Uninit_OverFile": "pe.size_of_uninitialized_data > filesize"},
    "ImageSize": {
        "H_Image_GT4x": "pe.size_of_image > 4 * filesize",
        "H_Image_GT8x": "pe.size_of_image > 8 * filesize",
        "H_Image_GT16x": "pe.size_of_image > 16 * filesize",
    },
    "Entropy": {
        "H_Entropy_GT65": "math.entropy(0, filesize) > 6.5",
        "H_Entropy_GT69": "math.entropy(0, filesize) > 6.9",
        "H_Entropy_GT73": "math.entropy(0, filesize) > 7.3",
        "H_Entropy_GT77": "math.entropy(0, filesize) > 7.7",
    },
}
ALL_PROBES = [p for variants in GROUPS.values() for p in variants]
KNOWN_RULES = set(ALL_PROBES) | {BASELINE, PE_RULE}


def pct(num: int, den: int) -> float:
    return round(100 * num / den, 2) if den else 0.0


def write_csv(path: Path, columns: list[str], records: list[dict]):
    with path.open("w", encoding="utf-8-sig", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)


def canonical(path: Path) -> str:
    # Windows paths are case-insensitive; casefold supports YARA's path spelling.
    return str(path.resolve()).casefold()


def scan(yara: Path, rules: Path, directory: Path, lookup: dict[str, int]) -> dict[str, set[int]]:
    print(f"Scanning {directory} (once)...", flush=True)
    command = [str(yara), "-r", str(rules), str(directory)]
    run = subprocess.run(command, capture_output=True, text=True,
                         encoding="utf-8", errors="replace", check=False)
    if run.returncode != 0:
        raise RuntimeError(
            f"YARA exited with code {run.returncode} on {directory}.\n"
            f"STDOUT: {run.stdout[:4000]}\nSTDERR: {run.stderr[:4000]}"
        )
    if run.stderr.strip():
        raise RuntimeError(f"YARA reported warnings/errors on {directory}:\n{run.stderr[:4000]}")
    hits = {rule: set() for rule in KNOWN_RULES}
    unknown = []
    for line in run.stdout.splitlines():
        if not line.strip():
            continue
        if " " not in line:
            unknown.append(line)
            continue
        rule, filename = line.split(" ", 1)
        if rule not in hits:
            unknown.append(line)
            continue
        key = canonical(Path(filename.strip()))
        if key not in lookup:
            unknown.append(line)
            continue
        hits[rule].add(lookup[key])
    if unknown:
        raise RuntimeError("Unexpected YARA output/path. Not counting partial results:\n" +
                           "\n".join(unknown[:12]))
    return hits


def mask_of(indices: set[int]) -> int:
    m = 0
    for ix in indices:
        m |= 1 << ix
    return m


def mask_for_choice(probe_masks: dict[str, int], choice: tuple[str, ...], minimum: int = 1) -> int:
    """Files matching at least 'minimum' independent attribute categories.

    The threshold options for any one category are mutually exclusive choices.
    """
    if minimum < 1 or minimum > len(choice):
        raise ValueError("Invalid minimum feature count")
    # A sample meets the threshold if it matches ANY k-way intersection.
    # Up to seven attributes, so at most 35 intersections per candidate.
    union = 0
    for subset in itertools.combinations(choice, minimum):
        intersection = probe_masks[subset[0]]
        for other in subset[1:]:
            intersection &= probe_masks[other]
        union |= intersection
    return union


def metrics(mask: int, malicious_mask: int, benign_mask: int):
    tp = (mask & malicious_mask).bit_count()
    fp = (mask & benign_mask).bit_count()
    return tp, fp


def build_rule(rule_name: str, selected: tuple[str, ...], minimum: int = 1) -> str:
    if len(selected) < 5:
        raise ValueError("Final rule must include at least five distinct PE attributes")
    if not 1 <= minimum <= len(selected):
        raise ValueError("Invalid minimum attribute count")
    expressions = {}
    for name in selected:
        for variants in GROUPS.values():
            if name in variants:
                expressions[name] = variants[name]
                break
    if len(expressions) != len(selected):
        raise ValueError("Unexpected attribute rule name")

    if minimum == 1:
        predicate = " or\n".join(f"            {expressions[name]}" for name in selected)
    else:
        # Logical disjunction of every k-way conjunction. Standard YARA syntax,
        # no dependence on Boolean arithmetic conversions or private subrules.
        clauses = []
        for subset in itertools.combinations(selected, minimum):
            clauses.append("            (" + " and ".join(expressions[name] for name in subset) + ")")
        predicate = " or\n".join(clauses)
    return (
        'import "pe"\nimport "math"\n\n'
        f'rule {rule_name} {{\n'
        '    meta:\n'
        '        description = "Lab 10 PE anomaly heuristics calibrated on a training split"\n'
        '        reference = "Joel Yonts, Attributes of Malicious Files (2012)"\n'
        '        caution = "Heuristic; thresholds are experimentally chosen, not indicators of certainty"\n'
        f'        minimum_suspicious_attributes = {minimum}\n'
        f'        distinct_attributes_in_rule = {len(selected)}\n'
        '    condition:\n'
        '        pe.is_pe and\n'
        '        (\n' + predicate + '\n'
        '        )\n'
        '}\n'
    )


def validate_yara(yara: Path, rule_paths: list[Path]):
    """Compile generated rules by scanning a tiny harmless test file, not malware."""
    with tempfile.TemporaryDirectory(prefix="yara-validation-") as temp:
        harmless = Path(temp) / "canary.txt"
        harmless.write_text("Harmless test file for YARA rule syntax validation\n", encoding="utf-8")
        for rule in rule_paths:
            run = subprocess.run([str(yara), str(rule), str(harmless)],
                                 capture_output=True, text=True, errors="replace")
            if run.returncode != 0:
                raise RuntimeError(f"Generated rule failed syntax check: {rule}\n{run.stderr}\n{run.stdout}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--yara", type=Path, default=DEFAULT_YARA)
    parser.add_argument("--rules", type=Path, default=HERE / "AdvancedOnePassProbes.yar")
    parser.add_argument("--output", type=Path, default=HERE / "AdvancedYaraResults")
    args = parser.parse_args()

    yara, rules, root, output = (p.resolve() for p in (args.yara, args.rules, args.dataset, args.output))
    for file in (yara, rules):
        if not file.is_file():
            raise SystemExit(f"Required file does not exist: {file}")

    malicious = root / "malicious"
    benign = root / "benign"
    for directory in (malicious, benign):
        if not directory.is_dir():
            raise SystemExit(f"Dataset directory does not exist: {directory}")

    samples = []
    for label, directory in (("malicious", malicious), ("benign", benign)):
        for file in sorted(directory.rglob("*")):
            if file.is_file():
                samples.append((label, file.resolve()))

    n_m = sum(label == "malicious" for label, _ in samples)
    n_b = len(samples) - n_m
    if not n_m or not n_b:
        raise SystemExit("Dataset must contain both malicious and benign samples")
    if len({canonical(f) for _, f in samples}) != len(samples):
        raise SystemExit("Duplicate canonical paths found; cannot safely count")

    lookup = {canonical(file): ix for ix, (_, file) in enumerate(samples)}
    print(f"Dataset: {n_m} malicious, {n_b} benign ({len(samples)} total)")
    malignant_hits = scan(yara, rules, malicious, lookup)
    benign_hits = scan(yara, rules, benign, lookup)
    all_hits = {name: malignant_hits[name] | benign_hits[name] for name in KNOWN_RULES}
    masks = {name: mask_of(all_hits[name]) for name in KNOWN_RULES}

    # Cross-check the original seven standalone predicates against the
    # unchanged baseline rule; refuse to report misleading numbers if the
    # probe expressions and baseline ever disagree.
    baseline_parts = (
        "H_Time_V1", "H_Sections_GT8", "H_Symbol_OutOfBounds",
        "H_Code_OverFile", "H_Uninit_OverFile", "H_Image_GT8x", "H_Entropy_GT69")

    if mask_for_choice(masks, baseline_parts) != masks[BASELINE]:
        raise RuntimeError("Sanity check failed: OR of original seven probes differs from baseline rule")
    pe_m_count = len(malignant_hits[PE_RULE]); pe_b_count = len(benign_hits[PE_RULE])
    print(f"Valid PE files: {pe_m_count}/{n_m} malicious, {pe_b_count}/{n_b} benign")


    rng = random.Random(20030)
    train_indices: set[int] = set()
    hold_indices: set[int] = set()
    for label in ("malicious", "benign"):
        ids = [i for i, (category, _) in enumerate(samples) if category == label]
        rng.shuffle(ids)
        n_hold = max(1, round(len(ids) * 0.25)) if len(ids) >= 4 else 0
        hold_indices.update(ids[:n_hold])
        train_indices.update(ids[n_hold:])

    train_m = mask_of({i for i in train_indices if samples[i][0] == "malicious"})
    train_b = mask_of({i for i in train_indices if samples[i][0] == "benign"})
    hold_m = mask_of({i for i in hold_indices if samples[i][0] == "malicious"})
    hold_b = mask_of({i for i in hold_indices if samples[i][0] == "benign"})
    total_m = mask_of({i for i, (label, _) in enumerate(samples) if label == "malicious"})
    total_b = mask_of({i for i, (label, _) in enumerate(samples) if label == "benign"})
    n_train_m, n_train_b = train_m.bit_count(), train_b.bit_count()
    n_hold_m, n_hold_b = hold_m.bit_count(), hold_b.bit_count()

    # One full YARA pass over each directory is sufficient for all comparisons.
    # Search ALL subsets of >= 5 distinct feature categories and ALL preset
    # threshold choices. No sample is rescanned during this search.
    base_train_tp, base_train_fp = metrics(masks[BASELINE], train_m, train_b)
    # The default candidate can flag NO MORE benign training samples than V1,
    # and is guaranteed to have a baseline-equivalent option in the search.
    budgets = {
        "BaselineFPBudget": base_train_fp,
        "FPR_025permille": int(0.025 * n_train_b),
        "FPR_050permille": int(0.05 * n_train_b),
        "FPR_075permille": int(0.075 * n_train_b),
        "FPR_100permille": int(0.10 * n_train_b),
    }
    best = {name: None for name in budgets}
    best_score = {name: None for name in budgets}
    count = 0
    groups = list(GROUPS)
    for group_count in (5, 6, 7):
        for selected_groups in itertools.combinations(groups, group_count):
            options = [list(GROUPS[g]) for g in selected_groups]
            for selected in itertools.product(*options):
                for minimum in (1, 2, 3):
                    if minimum > len(selected):
                        continue
                    count += 1
                    match_mask = mask_for_choice(masks, selected, minimum)
                    tp, fp = metrics(match_mask, train_m, train_b)
                    for budget_name, allowed_fp in budgets.items():
                        if fp <= allowed_fp:
                            # Prefer recall, then lower FP, fewer attribute
                            # categories, and higher minimum matched conditions.
                            # Never use holdout for selection.
                            score = (tp, -fp, -len(selected), minimum, tuple(selected))
                            if best_score[budget_name] is None or score > best_score[budget_name]:
                                best[budget_name] = (tuple(selected), minimum)
                                best_score[budget_name] = score
    print(f"Compared {count:,} attribute/threshold combinations on the training split.")

    output.mkdir(parents=True, exist_ok=True)
    indicators = []
    for name in [BASELINE, PE_RULE] + ALL_PROBES:
        total_tp, total_fp = metrics(masks[name], total_m, total_b)
        tr_tp, tr_fp = metrics(masks[name], train_m, train_b)
        val_tp, val_fp = metrics(masks[name], hold_m, hold_b)
        indicators.append({
            "Indicator": name, "TP": total_tp, "FP": total_fp,
            "DetectionPct": pct(total_tp, n_m), "FalsePositivePct": pct(total_fp, n_b),
            "TrainTP": tr_tp, "TrainFP": tr_fp,
            "HoldoutTP": val_tp, "HoldoutFP": val_fp,
        })
    write_csv(output / "IndicatorMetrics.csv", list(indicators[0]), indicators)

    candidates = [("Baseline_V1", None, 1, masks[BASELINE])]
    generated = []
    for budget_name, config in best.items():
        if config is None:
            print(f"No >=5-feature candidate met the {budget_name} budget")
            continue
        selected, minimum = config
        name = "Candidate_" + budget_name
        candidates.append((name, selected, minimum, mask_for_choice(masks, selected, minimum)))
        candidate_file = output / (name + ".yar")
        candidate_file.write_text(build_rule(name, selected, minimum), encoding="utf-8")
        generated.append(candidate_file)

    # PRESELECTED decision policy: maximise TRAINING detection without
    # increasing benign TRAINING matches relative to the V1 rule.  The
    # 25% held-out set is used only AFTER selection for evaluation.
    recommendation = next((entry for entry in candidates if entry[0] == "Candidate_BaselineFPBudget"),
                          candidates[0])
                    
    candidate_rows = []
    for name, selected, minimum, mask in candidates:
        tr_tp, tr_fp = metrics(mask, train_m, train_b)
        ho_tp, ho_fp = metrics(mask, hold_m, hold_b)
        t_tp, t_fp = metrics(mask, total_m, total_b)
        candidate_rows.append({
            "Candidate": name, "Indicators": "; ".join(selected) if selected else "Original 7 attributes",
            "MinimumMatchedAttributes": minimum,
            "TrainTP": tr_tp, "TrainFP": tr_fp,
            "TrainDetectionPct": pct(tr_tp, n_train_m), "TrainFalsePositivePct": pct(tr_fp, n_train_b),
            "HoldoutTP": ho_tp, "HoldoutFP": ho_fp,
            "HoldoutDetectionPct": pct(ho_tp, n_hold_m), "HoldoutFalsePositivePct": pct(ho_fp, n_hold_b),
            "TotalTP": t_tp, "TotalFN": n_m - t_tp, "TotalFP": t_fp, "TotalTN": n_b - t_fp,
            "TotalDetectionPct": pct(t_tp, n_m), "TotalFalsePositivePct": pct(t_fp, n_b),
            "TotalPrecisionPct": pct(t_tp, t_tp + t_fp),
            "TotalF1Pct": pct(2 * t_tp, 2 * t_tp + t_fp + (n_m - t_tp)),
            "TotalBalancedAccuracyPct": round((pct(t_tp, n_m) + pct(n_b - t_fp, n_b)) / 2, 2) })

    write_csv(output / "CandidateComparison.csv", list(candidate_rows[0]), candidate_rows)

    rec_name, rec_select, rec_minimum, rec_mask = recommendation
    rec_file = output / "Recommended_HeuristicV2.yar"
    if rec_select:
        rec_file.write_text(build_rule("Recommended_HeuristicV2", rec_select, rec_minimum), encoding="utf-8")
    else:
        # Baseline already satisfies >=5 attributes; regenerate under final name.
        unchanged = ("H_Time_V1", "H_Sections_GT8", "H_Symbol_OutOfBounds",
                     "H_Code_OverFile", "H_Uninit_OverFile", "H_Image_GT8x", "H_Entropy_GT69")
        rec_file.write_text(build_rule("Recommended_HeuristicV2", unchanged, 1), encoding="utf-8")
    generated.append(rec_file)
    validate_yara(yara, generated)

    file_rows = []
    fp_files, fn_files = [], []
    for ix, (label, file) in enumerate(samples):
        hit = bool((rec_mask >> ix) & 1)
        vals = [p for p in ALL_PROBES if ix in all_hits[p]]
        split = "holdout" if ix in hold_indices else "training"
        row = {
            "Label": label, "Split": split, "Path": str(file),
            "IsPE": int(ix in all_hits[PE_RULE]),
            "BaselineMatched": int(ix in all_hits[BASELINE]),
            "RecommendedMatched": int(hit),
            "MatchedIndicators": "; ".join(vals) }

        file_rows.append(row)
        if hit and label == "benign":
            fp_files.append(f"[{split}] {file}")
        if not hit and label == "malicious":
            fn_files.append(f"[{split}] {file}")
    write_csv(output / "FileLevelMatches.csv", list(file_rows[0]), file_rows)
    (output / "FalsePositiveFiles.txt").write_text("\n".join(fp_files) + "\n", encoding="utf-8")
    (output / "MissedMaliciousFiles.txt").write_text("\n".join(fn_files) + "\n", encoding="utf-8")

    summary = [
        "COS20030 Advanced YARA: one-pass heuristic study",
        f"Generated UTC: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total labelled files: {n_m} malicious / {n_b} benign",
        f"Valid PE files: {pe_m_count} malicious / {pe_b_count} benign",
        "Non-PE-labelled samples cannot match PE-gated rules.",
        f"Train: {n_train_m} malicious / {n_train_b} benign",
        f"Holdout: {n_hold_m} malicious / {n_hold_b} benign (25%, seeded; NOT used for optimisation)",
        f"Combinations evaluated on training split: {count}",
        "Note: training/holdout split is random by FILE, not malware family; correlated family variants may leak.",
        "Note: the seven PE attributes reflect the coursework V1; alternate thresholds are exploratory.",
        "Variants also evaluate requiring 1, 2 or 3 simultaneous anomalous PE attributes.",
        f"Default budget: no more than {base_train_fp} benign TRAINING matches, same as baseline V1.",
        "This guarantees >= baseline TRAINING true positives at <= baseline TRAINING false positives.",
        "Resulting YARA rules are syntax-checked against a harmless canary file, NOT rescanned on the dataset.",
        "Scans: one recursive YARA execution per class directory; no samples executed.",
        "",
        "NAME | FULL TP/FP | FULL DETECTION% / FPR% | HOLDOUT DETECTION% / FPR%" ]

    for row in candidate_rows:
        summary.append(
            f"{row['Candidate']} | {row['TotalTP']}/{row['TotalFP']} | "
            f"{row['TotalDetectionPct']}/{row['TotalFalsePositivePct']} | "
            f"{row['HoldoutDetectionPct']}/{row['HoldoutFalsePositivePct']}" )

    summary.extend([
        "",
        f"PRESELECTED RECOMMENDATION: {rec_name} (minimum {rec_minimum} matched attribute(s))",
        ("Recommendation optimised only using TRAINING samples and baseline-FP budget."
         if rec_select else
         "No candidate met baseline-FP budget; baseline retained."),
        "Review the HOLDOUT false-positive rate before claiming improvement.",
        "Comparing candidates on holdout to choose again would compromise independent validation.",
        "The generated rule satisfies the >=5 distinct PE-attribute condition constraint.",
        "A false-positive rate of 0% on a small holdout does not prove zero risk in production.",
        "",
        "OUTPUT FILES:",
        "  IndicatorMetrics.csv          individual rule results",
        "  CandidateComparison.csv       train/holdout/full evaluation",
        "  FileLevelMatches.csv          evidence for every dataset file",
        "  Recommended_HeuristicV2.yar  selected YARA rule",
        "  Candidate_*.yar              alternatives selected on training data",
        "  FalsePositiveFiles.txt / MissedMaliciousFiles.txt",
    ])
    (output / "StudySummary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n" + "\n".join(summary[:min(len(summary), 22)]))
    print(f"\nAll outputs saved in: {output}")


if __name__ == "__main__":
    main()
