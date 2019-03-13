
rule memory_win_generic_jar_appended_to_msi
{
  meta:
    author = "raw-data"
    tlp = "WHITE"

    version = "1.0"
    created = "2019-01-17"
    modified = "2019-01-17"

    description = "Detects malicious JAR appended to MSI"
    reference = "https://blog.virustotal.com/2019/01/distribution-of-malicious-jar-appended.html"
    
    strings:

        // MSI
        $msi = {D0 CF}
        $msi1 = {52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79}
        $msi2 = "Installation Database" fullword ascii
        $msi3 = "Windows Installer XML" fullword ascii

        // malicious JAR appended to MSI
        $jar1 = {50 4B 03 04 14}
        $jar2 = {2F 50 4B}
        $jar3 = {2E 63 6C 61 73 73}
    
    condition:
        (
           (3 of ($msi*) and (2 of ($jar*)))
        )
}