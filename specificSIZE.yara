rule Find_Large_Files
{
    meta:
        description = "Find files larger than 10MB"
        author = "Joey Cadieux"

    condition:
        filesize > 10485760 // 10MB in bytes
}