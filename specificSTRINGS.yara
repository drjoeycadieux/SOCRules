rule Find_Malware_Strings
{
    meta:
        description = "Find files containing potential malware strings"
        author = "Joey Cadieux"

    strings:
        $malware1 = "backdoor"
        $malware2 = "ransomware"
        $malware3 = "trojan"

    condition:
        any of them
}