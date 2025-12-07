rule TestMalware {
    meta:
        description = "Test malware detection rule"
        author = "WinnCoreAV"
        date = "2024-11-16"
        
    strings:
        $exec1 = "/bin/sh" ascii
        $exec2 = "/bin/bash" ascii
        $download = "wget" ascii
        $curl = "curl" ascii
        $suspicious1 = "LD_PRELOAD" ascii
        $suspicious2 = "setuid" ascii
        
    condition:
        any of them
}

rule CompromisedBinary {
    meta:
        description = "Potentially compromised binary indicators"
        
    strings:
        $shell = { 2f 62 69 6e 2f 73 68 }  // "/bin/sh" in hex
        $exec_syscall = { b8 3b 00 00 00 }   // execve syscall (x86_64)
        
    condition:
        any of them
}
