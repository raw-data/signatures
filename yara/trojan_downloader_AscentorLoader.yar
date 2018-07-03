
rule trojan_downloader_AscentorLoader
{

  meta:
    author = "raw-data"
    tlp = "WHITE"

    type = "PE32 executable (GUI) Intel 80386, for MS Windows"
    version = "1.0"
    created = "2018-06-18"
    modified = "2018-06-18"

    description = "Trojan-downloader.Win32.AscentorLoader"
    reference = "https://twitter.com/VK_Intel/status/1008487036922130432"

    hash_256 = "04e6a3715bc818bea17da9608e1b66c7ccff15f96018b0acdb351d4ca727d0d4"

  strings:
    $gs1 = "Host: %s" fullword ascii
    $gs2 = "User-Agent: %s" fullword ascii
    
    $gh1 = {66 00 75 00 63 00 6B 00 20 00 74 00 68 00 69 00
            73 00 20 00 62 00 6F 00 72 00 69 00 6E 00 67 00
            20 00 68 00 61 00 73 00 68 00 20 00 69 00 6D 00 
            70 00 6F 00 72 00 74}

    $gh2 = {64 65 62 75 67 2E 74 78 74}

    $gh3 = {C7 85 E0 ?? ?? ?? 1C 01 00 00 ?? ?? 89 BD E4 ?? 
            ?? ?? 68 FE 00 ?? ?? 66 89 85 ?? ?? ?? FF 8D 85
            F6 ?? ?? ??}
    
    $sh1 = {6E 61 6F 5F 73 65 63 5F 67 6F 6D 6F 73 65 63 3D}
    $sh2 = {41 73 63 65 6E 74 6F 72 4C 6F 61 64 65}

  condition:
    (
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 200KB)
        and
        (
                (any of ($gs*)) and  (( 2 of ($gh*)) and (any of ($sh*)))
        )

    )
    or

    (
        (any of ($gs*)) and  (( 2 of ($gh*)) and (any of ($sh*)))
    )
}