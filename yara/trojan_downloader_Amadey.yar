rule trojan_downloader_amadey
{

  meta:
    author = "raw-data"
    tlp = "WHITE"

    version = "1.0"
    created = "2018-11-12"
    modified = "2018-11-12"

    description = "Trojan-downloader.Win32.Amadey"

    hash_256 = "2ee5027181db385e9cfa1ac30b3ee1752f851bc38cb8c284a6270c09414cf406"

 strings:

    $ssf1 = "SYSINFORMATION:" fullword ascii
    $ssf2 = "ProductName" fullword wide
    $ssf3 = "MachineGuid" fullword wide
    $ssf4 = "IP: %s" fullword ascii
    $ssf5 = "User: %s" fullword ascii
    $ssf6 = "Layouts:" fullword ascii

    $sss1 = "username_value" fullword ascii
    $sss2 = "password_value" fullword ascii
    $sss3 = "name_on_card" fullword ascii
    $sss4 = "wallet_path" fullword wide
    $sss5 = ".wallet" fullword wide
    $sss6 = "%s\\%s\\main.db" fullword wide
    $sss7 = "Skype\\%s.txt" fullword wide
    $sss8 = "%slogins.json" fullword wide
    $sss9 = "%ssignons.sqlite" fullword wide

    $ssn1 = "%S/base64.php?_f=%s" fullword wide
    $ssn2 = "%s/%s.php" fullword ascii
    $ssn3 = "%s/gate.php" fullword ascii
    $ssn4 = "_PWD_" fullword ascii
    $ssn5 = "_COOOOKIE_" fullword ascii
    $ssn6 = "_CREDIT_CARD_" fullword ascii
    $ssn7 = "_AUTOFILL_DATA_" fullword ascii
    $ssn8 = "%s | %s | %s | %02d/%04d | %s" fullword ascii

 condition:
    (
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 100KB)
        and
        (
            (2 of ($ssf*) and  4 of ($sss*) and 2 of ($ssn*))
        )
    )
    or
    (
        (2 of ($ssf*) and  4 of ($sss*) and 2 of ($ssn*))
    )
    
}