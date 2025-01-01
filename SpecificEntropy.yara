rule Find_High_Entropy_Files
{
    meta:
        description = "Find files with high entropy"
        author = "Joey Cadieux"

    condition:
        entropy > 7.0 // Adjust threshold as needed
}