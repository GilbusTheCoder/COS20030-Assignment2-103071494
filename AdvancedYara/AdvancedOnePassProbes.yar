import "pe"
import "math"

// COS20030 Section 12 - probing individual PE attributes.

rule Advanced_PE_HeuristicV1 {
    meta:
        description = "Original seven-attribute baseline, unchanged"
        version = "1.0"
    condition:
        pe.is_pe and (
            pe.timestamp < 694224000 or
            pe.timestamp > 1798761600 or
            pe.number_of_sections > 8 or
            (pe.pointer_to_symbol_table > 0 and pe.pointer_to_symbol_table >= filesize) or
            pe.size_of_code > filesize or
            pe.size_of_uninitialized_data > filesize or
            pe.size_of_image > 8 * filesize or
            math.entropy(0, filesize) > 6.9
        )
}

rule P_IsPE { condition: pe.is_pe }

rule H_Time_V1 { condition: pe.is_pe and (pe.timestamp < 694224000 or pe.timestamp > 1798761600) }
rule H_Time_Pre1992 { condition: pe.is_pe and pe.timestamp < 694224000 }
rule H_Time_Pre2000 { condition: pe.is_pe and pe.timestamp < 946684800 }
rule H_Time_Zero { condition: pe.is_pe and pe.timestamp == 0 }
rule H_Time_Future2027 { condition: pe.is_pe and pe.timestamp > 1798761600 }
rule H_Time_VeryFuture2030 { condition: pe.is_pe and pe.timestamp > 1893456000 }

rule H_Sections_GT6 { condition: pe.is_pe and pe.number_of_sections > 6 }
rule H_Sections_GT8 { condition: pe.is_pe and pe.number_of_sections > 8 }
rule H_Sections_GT10 { condition: pe.is_pe and pe.number_of_sections > 10 }

rule H_Symbol_OutOfBounds {
    condition:
        pe.is_pe and pe.pointer_to_symbol_table > 0 and
        pe.pointer_to_symbol_table >= filesize
}

rule H_Code_OverFile { condition: pe.is_pe and pe.size_of_code > filesize }
rule H_Uninit_OverFile { condition: pe.is_pe and pe.size_of_uninitialized_data > filesize }

rule H_Image_GT4x { condition: pe.is_pe and pe.size_of_image > 4 * filesize }
rule H_Image_GT8x { condition: pe.is_pe and pe.size_of_image > 8 * filesize }
rule H_Image_GT16x { condition: pe.is_pe and pe.size_of_image > 16 * filesize }

rule H_Entropy_GT65 { condition: pe.is_pe and math.entropy(0, filesize) > 6.5 }
rule H_Entropy_GT69 { condition: pe.is_pe and math.entropy(0, filesize) > 6.9 }
rule H_Entropy_GT73 { condition: pe.is_pe and math.entropy(0, filesize) > 7.3 }
rule H_Entropy_GT77 { condition: pe.is_pe and math.entropy(0, filesize) > 7.7 }