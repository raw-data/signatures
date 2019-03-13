rule win_trojan_downloader_ddkong
{

  meta:
    author = "raw-data"
    tlp = "WHITE"

    type = "PE32 executable (DLL) (GUI) Intel 80386, for MS Windows"
    version = "1.0"
    created = "2018-06-26"
    modified = "2018-06-26"

    description = "Trojan-Downloader.Win32.DDKong"
    reference = "https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/"

    hash256 = "113ae6f4d6a2963d5c9a7f42f782b176da096d17296f5a546433f7f27f260895"
    hash256 = "128adaba3e6251d1af305a85ebfaafb2a8028eed3b9b031c54176ca7cef539d2"
    hash256 = "15f4c0a589dff62200fd7c885f1e7aa8863b8efa91e23c020de271061f4918eb"

  strings:
    $gs1 = "%s \"%s\", Install" fullword ascii
    $gs2 = "%s \"%s\",Rundll32Call" fullword ascii
    $gs3 = "RunShellCode!" fullword ascii
    $gs4 = "BypassUacWithInject: %s!" fullword ascii

    $ss1 = "%s\\KingKong.dll" fullword ascii
    $ss2 = "%s\\drv1028.sys" fullword ascii
    $ss3 = "%s\\AdTt%d.dll" fullword ascii
    $ss4 = "%s \"%s\", NewCopyOutOfUAC" fullword ascii
    $ss5 = "%allusersprofile%\\BaseKst" fullword ascii
    $ss6 = "send buf null, size %d" fullword ascii
    $ss7 = "send head failed %p" fullword ascii

    $gh1 = {63 6D 64 20 2F 63 20 72 64 20 22 25 73 22 20 2F 73 20 2F 71}
    $gh2 = {63 6D 64 20 2F 63 20 64 65 6C 20 22 25 73 5C 2A 2E 2A 22 20 2F 66 20 2F}
    $gh3 = {63 6D 64 20 2F 63 20 73 63 20 64 65 6C 65 74 65 20 22 25 73 22}
    $gh4 = {63 6D 64 20 2F 63 20 73 63 20 73 74 6F 70 20 22 25 73 22}
    
    $sh = {80 ?? ?? ?? 40 3B ?? ?? 72 ??}

  condition:
    (
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 100KB)
        and
        (
            (1 of ($gs*)) and (4 of ($ss*)) or ((2 of ($gh*)) and $sh )
        )
    )
    or
    (
        (1 of ($gs*)) and (4 of ($ss*)) or ((2 of ($gh*)) and $sh )
    )
    
}