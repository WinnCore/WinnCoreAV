rule TestVirus
{
    meta:
        description = "Test virus signature for CI/CD testing"
        author = "WinnCoreAV"
        date = "2025-11-01"

    strings:
        $test_string = "WINNCORE_TEST_SIGNATURE"

    condition:
        $test_string
}

rule EICARTestFile
{
    meta:
        description = "EICAR test file signature (safe test pattern)"
        author = "WinnCoreAV"
        reference = "https://www.eicar.org/"

    strings:
        // Using obfuscated pattern to avoid triggering AV scanners
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 }

    condition:
        $eicar
}
