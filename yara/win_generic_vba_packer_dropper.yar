rule win_generic_vba_packer_dropper
{

  meta:
    author = "raw-data"
    tlp = "WHITE"

    version = "1.0"
    created = "2018-10-31"
    modified = "2018-10-31"

    description = "generic_vba_packer_dropper"

 strings:

  	$gs1 = "MSVBVM60.DLL" fullword ascii
 	$gs2 = "VB5!6&*" fullword ascii
 	$gs3 = "VBA6.DLL" fullword ascii
    $gs4 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii

 	$gs_1 = "__vbaFreeObj" fullword ascii
 	$gs_2 = "__vbaFreeVarList" fullword ascii
 	$gs_3 = "__vbaStrToUnicode" fullword ascii
 	$gs_4 = "__vbaStrToAnsi" fullword ascii
 	$gs_5 = "__vbaFreeStr" fullword ascii
 	$gs_6 = "__vbaStrCopy" fullword ascii
    $gs_7 = "__vbaExceptHandler" fullword ascii

 	$ss1 = "RtlMoveMemory" fullword ascii
 	$ss2 = "DllFunctionCall" fullword ascii
 	$ss3 = "GetFileVersionInfoA" fullword ascii
 	$ss4 = "GetFileVersionInfoSizeA" fullword ascii
 	$ss5 = "Version.dll" fullword ascii
    $ss6 = "EnumResourceTypesW" fullword ascii
    $ss7 = {65 00 78 00 65}

 condition:
    (
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550))
        and
        (
            (2 of ($gs*)) and (3 of ($gs_*)) and (2 of ($ss*))
        )
    )
    or
    (
        (2 of ($gs*)) and (3 of ($gs_*)) and (2 of ($ss*))
    )
    
}