$yara = "C:\Users\student\Tools\yara64.exe"
$rule = ".\AdvancedHeuristic.yar"

$malicious = @(& $yara -r $rule ".\malicious")
$malExit = $LASTEXITCODE

$benign = @(& $yara -r $rule ".\benign")
$benExit = $LASTEXITCODE

if ($malExit -ne 0 -or $benExit -ne 0) {
    throw "YARA reported an error... Check output before counting" 
}

$malicious | Set-Content ".\malicious_matches.txt"
$benign | Set-Content ".\benign_matches.txt"

$tp = $malicious.Count 
$fp = $benign.Count 

$recall = [math]::Round(($tp / 346) * 100, 2)
$fpr = [math]::Round(($fp / 376) * 100, 2)

Write-Host " ----------------- Advanced Yara Metrics ----------------- "
Write-Host "Malicious detected: $tp / 346"
Write-Host "Benign flagged:     $fp / 376"
Write-Host "Detection rate:     $recall %"
Write-Host "False positives:    $fpr %"