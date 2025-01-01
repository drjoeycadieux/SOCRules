rule Find_Suspicious_PE_Files
{
    meta:
        description = "Find PE files with suspicious characteristics"
        author = "Joey Cadieux"

    strings:
        $pe_header = { 45 50 } // "PE" signature

    condition:
        uint16(0) == 0x5A4D // MZ header
        uint32(0x3C) > 0 // Offset to PE header
        uint32(0x3C) < 0x1000 // Reasonable offset range
        filesize > 0x200 // Minimum file size for a PE file
        $pe_header at 0x3C
}