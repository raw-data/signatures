rule trojan_downloader_azorult
{

  meta:
    author = "raw-data"
    tlp = "WHITE"

    version = "1.0"
    created = "2018-11-12"
    modified = "2018-11-12"

    description = "Trojan-Spy.Win32.AZORult"

    hash_256 = "093a028e71c46e34862a5e8d77161e029307fc8eed332146ac6d2cbf929612c3"

 strings:

    $ssf1 = "USER:" fullword ascii
    $ssf2= "Computer(Username) :" fullword ascii
    $ssf3 = "GetRAM:" fullword ascii
    $ssf4 = "MachineGuid" fullword wide
    $ssf5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
    $ssf6 = "Computer(Username) :" fullword ascii
    $ssf7 = "Screen:" fullword ascii
    $ssf8 = "Layouts:" fullword ascii

    $sss1 = "Telegram" fullword wide
    $sss2 = "<password>" fullword ascii
    $sss3 = "Pass" fullword wide
    $sss4 = "PASS:" fullword ascii
    $sss5 ="\\accounts.xml" fullword wide
    $sss6 = "<account>" fullword ascii
    $sss7 = "<protocol>" fullword ascii
    $sss8 = "<name>" fullword ascii
    $sss9 = "%APPDATA%\\.purple\\accounts.xml" fullword wide
    $sss10 = "%TEMP%\\curbuf.dat" fullword wide
    $sss11 = "%APPDATA%\\Skype" fullword wide
    $sss12 = "SteamPath" fullword wide
    $sss13 = "Software\\Valve\\Steam" fullword wide

    $hs1 = {6d 6f 7a 5f 68 69 73 74 6f 72 79 76 69 73 69 74 73 2e 76 69 73 69 74 5f 64 61 74 65}
    $hs2 = {6d 6f 7a 5f 68 69 73 74 6f 72 79 76 69 73 69 74 73}
    $hs3 = {76 69 73 69 74 73 2e 76 69 73 69 74 5f 74 69 6d 65}

 condition:
    (
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 500KB)
        and
        (
            (3 of ($ssf*) and  5 of ($sss*) and 1 of ($hs*))
        )
    )
    or
    (
        (3 of ($ssf*) and  5 of ($sss*) and 1 of ($hs*))
    )
    
}
