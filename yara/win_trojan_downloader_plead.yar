import "math"
import "pe"

rule win_trojan_downloader_plead
{

  meta:
    author = "raw-data"
    tlp = "WHITE"

    type = "PE32 executable (GUI) Intel 80386, for MS Windows"
    version = "1.0"
    created = "2018-06-11"
    modified = "2018-06-11"

    description = "Trojan-downloader.Win32.PLEAD"
    reference = "https://blog.jpcert.or.jp/2018/06/plead-downloader-used-by-blacktech.html"

    hash_256 = "a26df4f62ada084a596bf0f603691bc9c02024be98abec4a9872f0ff0085f940"

  strings:
    $x1 = "WmiPrvSE.hlp" fullword ascii
    $x2 = "WmiPrvSE.rtf" fullword ascii
    $x3 = "<program name unknown>" fullword ascii

    $c1 = "%02d-%02d-%02d" fullword ascii
    $c2 = "SysListView32" fullword ascii
    $c3 = "%02d:%02d:%02d" fullword ascii
    $c4 = "Checking..." fullword wide
    $c5 = "ppxxxx" fullword ascii

  condition:
    (
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 500KB)
        and
        (
            for any i in (0..pe.number_of_sections - 1): (
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >=6
            )
        )
        and
        (
            (any of ($x*)) and (3 of ($c*))
        )
    )
    or
    ((any of ($x*)) and (5 of ($c*)))
}