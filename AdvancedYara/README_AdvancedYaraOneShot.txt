!!! IF IT BREAKS ITS PROBABLY A PATH ISSUE !!!

COS20030 – ADVANCED YARA ONE-SHOT EVALUATION
WHAT'S INCLUDED
    AdvancedOnePassProbes.yar - Baseline and 20 independent PE-anomaly tests
    AdvancedYaraOneShot.py    - Scans twice (once per directory), analyses results
    AdvancedYaraOneShot.ps1   - One-command PowerShell launcher

PROCESS
- Count labelled malicious and benign files automatically.
- Run YARA once recursively per directory.
- Recover per-file matches for 20 individual tests, the baseline rule, and PE gating.
- Evaluate 7,623 combinations of thresholds and 1-of / 2-of / 3-of categories offline.
- Choose a candidate using 75% of each label class (random seeded split),
  with no increase in benign matches compared with baseline on the training split.
- Evaluate that fixed recommendation on the remaining 25% holdout.
- Export detailed results and final candidate YARA rule(s), then syntax-check them
  using a harmless canary text file (NOT by rescanning malware).

OUTPUTS (written to the AdvancedYaraResults subfolder)
    StudySummary.txt               - console/report-friendly summary
    CandidateComparison.csv        - baseline and candidates: training, holdout, full
    IndicatorMetrics.csv           - per-rule comparison
    FileLevelMatches.csv           - which criteria matched each sample
    Recommended_HeuristicV2.yar   - selected rule; >= 5 distinct criteria
    Candidate_*.yar                - other false-positive limits
    FalsePositiveFiles.txt        - flagged benign paths
    MissedMaliciousFiles.txt      - unflagged malicious paths

