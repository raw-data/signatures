import "pe"

rule win_trojan_net_dropper
{

 meta:
    author = "raw-data"
    tlp = "WHITE"

    type = "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows"
    version = "1.0"
    created = "2018-07-03"
    modified = "2018-07-03"

    description = "Trojan-Dropper.Win32.Generic"
    reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/malicious-macro-hijacks-desktop-shortcuts-to-deliver-backdoor/"

    hash_256 = "45b2580db6d13720014753813eb69c1aa0effbd100bb80e5a07d75447489ba0f"
    hash_256 = "7730a98fd698f1043184992f1ca349ea1bdfd33d43a0ece2cd88f9f6da2e37d1"
    hash_256 = "2b3cd4d85b2b1f22d88db07352fb9e93405f395e7d0cfe96490ea2bc03a8c5ff"
    hash_256 = "cc60dae1199c72543dd761c921397f6e457ff0440da5b4451503bfca9fb0c730"
    hash_256 = "a4b25e5e72fc552e30391d7cd8182af023dc1084641d93b7fa6f348e89b29492"

 strings:
 	$gh1 = {64 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6F 00 6E}
 	$gh2 = {44 00 69 00 73 00 70 00 6C 00 61 00 79 00 4E 00 61 00 6D 00 65 00 3D}
 	$gh3 = {73 00 74 00 61 00 72 00 74 00 3D}
    $gh4 = {4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00}

 	$sh1 = {74 6F 72 6E 65 78 6C 74 64 40 65 75 72 6F 70 61 6D 65 6C 2E 6E 65 74}
	$sh2 = {54 4F 52 4E 45 58 20 4C 54 44}
 	$sh3 = {57 00 50 00 4D 00 20 00 50 00 72 00 6F 00 76 00 69 00 64 00 65 00 72 00 20 00 48 00 6F 00 73 00 74}

 condition:
     (
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 2MB)
        and
        (
		    for any i in (0..pe.number_of_signatures):
		                 (pe.signatures[i].serial == "66:41:27:c5:2a:69:19:6a:a6:ad:99:b9:42:24:8a:b3")
        )
        and
        (
        	(3 of ($gh*))
        )
    )
    or
    (
    	(3 of ($gh*)) and (2 of ($sh*))
    )

}

