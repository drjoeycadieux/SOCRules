rule Find_Executable_Files
{
    meta:
        description = "Find files with common executable extensions"
        author = "Joey Cadieux"

    strings:
        $exe1 = { 45 78 65 } // .exe
        $exe2 = { 44 4C 4C } // .dll

    condition:
        any of them
}