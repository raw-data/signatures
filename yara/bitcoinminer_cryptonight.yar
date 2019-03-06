rule bitcoinminer_cryptonight
{
    meta:
    author = "raw-data"
    tlp = "WHITE"

    type = "ELF 64-bit LSB  executable, x86-64, version 1 (GNU/Linux), statically linked, stripped"
    version = "1.0"
    created = "2018-11-08"
    modified = "2018-11-08"

    description = "RiskTool.Linux.BitCoinMiner.Cryptonight"

    hash256 = "7534ffc934904962dc01d2ee6ca207a7f07002cd1351ca6377c2cdd8feab59ff"
    hash256_unpacked = "365198ed4f1205c42fa448d41c9088d3dea6bff43173c5e870e8bec4631c3a7d"

    strings:
        
        $gs1 = "Atom(TM) CPU"
        $gs2 = "Pentium(R) Dual  CPU"
        $gs3 = "Pentium(R) Dual-Core"
        $gs4 = "Genuine Intel(R) CPU"

        $ss1 = "cryptonight-light" fullword ascii
        $ss2 = "cryptonight-lite" fullword ascii
        $ss3 = "cryptonight-heavy" fullword ascii

        $hss = {?? 63 72 79 70 74 6F 6E 69 67 68 74}
    
    condition:
        (
            ((uint16(0) == 0x457F) and (filesize > 4MB and filesize < 5MB))
                and
            (
                (2 of ($gs*) and ( (2 of ($ss*)) or $hss) )
            )

        )
        or
        (
            (2 of ($gs*) and ( (2 of ($ss*)) or $hss) )
        )

}
