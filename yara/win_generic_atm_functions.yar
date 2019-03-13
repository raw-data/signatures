
rule win_generic_atm_functions
{

  meta:
    author = "raw-data"
    tlp = "white"

    version = "1.0"
    created = "2019-01-13"
    modified = "2019-01-13"

    description = "Detects access to common dll, program or functions usually called by / found in ATM malware"

  strings:

    $gs1 = "MSXFS.dll" fullword ascii
    $gs2 = "DbdDevAPI.dll" fullword ascii
    $gs3 = "ncr.aptra.axfs.activexfscontrols.dll" fullword ascii
    $gs4 = "K3A.Platform.dll" fullword ascii
    $gs5 = "NCR.APTRA.AXFS" fullword ascii
    $gs6 = "IDCardUnit1" fullword ascii
    $gs7 = "DBD_MotoCardRdr" fullword ascii
    $gs8 = "Diebold" fullword ascii
    $gs9 = "C:\\Program Files\\NCR Aptra\\bin\\NCRPRS.exe" fullword ascii
    $gs10 = "C:\\Program Files\\Diebold\\Agilis Startup\\DBackup.exe" fullword ascii
    $gs11 = "C:\\Probase\\cscw32\\bin\\FwLoadPm.exe" fullword ascii

    $msxfsf1 = "WFSClose" fullword ascii
    $msxfsf2 = "WFSAsyncExecute" fullword ascii
    $msxfsf3 = "WFSFreeResult" fullword ascii
    $msxfsf4 = "WFSGetInfo" fullword ascii
    $msxfsf5 = "WFSExecute" fullword ascii
    $msxfsf6 = "WFSRegister" fullword ascii
    $msxfsf7 = "WFSOpen" fullword ascii
    $msxfsf8 = "WFSCancelAsyncRequest" fullword ascii
    $msxfsf9 = "WFSStartUp" fullword ascii
    $msxfsf10 = "WFSCleanUp" fullword ascii
    $msxfsf11 = "WFMQueryValue" fullword ascii
    $msxfsf12 = "WFMOpenKey" fullword ascii
    $msxfsf13 = "WFMEnumKey" fullword ascii
    $msxfsf14 = "WFMCloseKey" fullword ascii

    $oxfs1 = "XFSPTR" fullword ascii
    $oxfs2 = "XFSIDC" fullword ascii
    $oxfs3 = "XFSCDM" fullword ascii
    $oxfs4 = "XFSPIN" fullword ascii
    $oxfs5 = "XFSVDM" fullword ascii

  condition:

    (
        ((uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550))
        and
        (
            ((1 of ($msxfsf*)) and (1 of ($gs*)))
                or
            ((1 of ($oxfs*)) and (1 of ($gs*)))
        )
    )
    or
    (
        ((1 of ($msxfsf*)) and (1 of ($gs*)))
            or
        ((1 of ($oxfs*)) and (1 of ($gs*)))
    )
    
}