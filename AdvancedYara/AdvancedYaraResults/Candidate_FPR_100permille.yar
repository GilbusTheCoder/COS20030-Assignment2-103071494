import "pe"
import "math"

rule Candidate_FPR_100permille {
    meta:
        description = "Lab 10 PE anomaly heuristics calibrated on a training split"
        reference = "Joel Yonts, Attributes of Malicious Files (2012)"
        caution = "Heuristic; thresholds are experimentally chosen, not indicators of certainty"
        minimum_suspicious_attributes = 1
        distinct_attributes_in_rule = 5
    condition:
        pe.is_pe and
        (
            pe.timestamp < 946684800 or
            pe.number_of_sections > 8 or
            pe.size_of_uninitialized_data > filesize or
            pe.size_of_image > 4 * filesize or
            math.entropy(0, filesize) > 6.9
        )
}
