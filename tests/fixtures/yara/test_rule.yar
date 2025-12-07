rule test_malware {
    strings:
        $a = "EVIL_STRING"
    condition:
        $a
}
