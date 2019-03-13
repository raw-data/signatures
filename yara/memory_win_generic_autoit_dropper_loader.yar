rule memory_win_generic_autoit_dropper_loader
{
    meta:
        author = "raw-data"
        tlp = "WHITE"

        version = "1.0"
        created = "2018-11-25"
        modified = "2018-11-25"

        description = "AutoItDropperLoader"

        sha256 = "446e4175757532c905ed92bf503a3175747e0609c482c1e3fa8c2ca09e71da66"
        sha256 = "9795ec58177e53940db2f5cb18ff9f2e77398523aea610a2abf5500f18ddda46"

    strings:

        $a1 = "AutoIt3GUI" fullword wide
        $a2 = "AutoIt v3 Script" fullword wide
        $a3 = "AutoIt3.exe" fullword wide
        $a4 = "AUTOITWINSETTITLE" fullword wide

        $gs1 = "ProcessExists" nocase wide ascii
        $gs2 = "Execute" nocase wide ascii
        $gs3 = "Sleep" nocase wide ascii
        $gs4 = "@ScriptDir" nocase wide ascii
        $gs5 = "FileWrite" nocase wide ascii
        $gs6 = "FileSetAttrib" nocase wide ascii
        $gs7 = "IniRead" nocase wide ascii
        $gs8 = "Random" nocase wide ascii
        $gs9 = "DllStructSetData" nocase wide ascii
        $gs10 = "DllCall" nocase wide ascii
        $gs11 = "user32.dll" nocase wide ascii
        $gs12 = "FileDelete" nocase wide ascii
        $gs13 = "Shutdown" nocase wide ascii
        $gs14 = "FileGetShortName" nocase wide ascii
        $gs15 = "@ScriptFullPath" nocase wide ascii
        $gs16 = "BinaryToString" nocase wide ascii
        $gs17 = "StringReplace" nocase wide ascii
        $gs18 = "Setting" nocase wide ascii
        $gs19 = "CallWindowProc" nocase wide ascii
        
        $dll1 = "user32.dll" nocase wide ascii
        $dll2 = "7573657233322e646c6c" nocase wide ascii
        $dll3 = "Advapi32.dll" nocase wide ascii
        $dll4 = "41647661706933322e646c6c" nocase wide ascii
        $dll5 = "kernel32.dll" nocase wide ascii
        $dll6 = "6b65726e656c33322e646c6c" nocase wide ascii
        $dll7 = "ntdll.dll" nocase wide ascii
        $dll8 = "6e74646c6c2e646c6c" nocase wide ascii
        $dll9 = "TerminateProcess" nocase wide ascii
        $dll10 = "VirtualAllocEx" nocase wide ascii
        $dll11 = "NtUnmapViewOfSection" nocase wide ascii

    condition:
        (6 of ($gs*) and not 1 of ($a*)) 
            or
        (6 of ($gs*) and 2 of ($dll*) and not 1 of ($a*))
}
