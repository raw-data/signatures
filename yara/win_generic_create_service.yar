
rule win_generic_create_service
{
  meta:
    author = "raw-data"
    tlp = "WHITE"

    version = "1.0"
    created = "2018-11-05"
    modified = "2019-03-13"

    description = "Track Windows Service creation"

  strings:

    $ss1 = "CreateServiceA" fullword ascii
    $ss2 = "CloseServiceHandle" fullword ascii
    $ss3 = "OpenServiceA" fullword ascii
    $ss4 = "ChangeServiceConfig2A" fullword ascii
    $ss5 = "DeleteService" fullword ascii
    $ss6 = "StartServiceA" fullword ascii
    $ss7 = "RegisterServiceCtrlHandlerA" fullword ascii
    $ss8 = "StartServiceCtrlDispatcherA" fullword ascii
    $ss9 = "SetServiceStatus" fullword ascii

  condition:
    (
      (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550)
        and
        (
            (3 of ($ss*))
        )

    )
    or

    (
        (3 of ($ss*))
    )
}
