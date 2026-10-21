import "pe"
import "math"

rule Advanced_PE_HeuristicV1 {
    meta:
        description = "Heuristic PE MW detection via anomalous file attributes"
        author = "Thomas Horsley 103071494"
        reference = "Joel Yonts - Attributes of Malicious Files (2012)"
        version = "1.0"

    condition:  
        pe.is_pe and 
        (
            // Sus compilation times
            pe.timestamp < 694224000 or
            pe.timestamp > 17987616000 or

            // sus section count
            pe.number_of_sections > 8 or

            // sus coff allocations
            (pe.pointer_to_symbol_table > 0 and pe.pointer_to_symbol_table >= filesize) or
            
            // sus data quantity
            pe.size_of_code > filesize or 
            pe.size_of_uninitialized_data > filesize or
            pe.size_of_image > 8 * filesize or

            // sus entropy
            math.entropy(0, filesize) > 6.9
        )

}