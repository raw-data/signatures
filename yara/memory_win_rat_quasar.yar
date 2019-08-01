
rule memory_win_rat_quasar
{

  meta:
    author = "raw-data"
    tlp = "WHITE"

    version = "1.0"
    created = "2019-07-19"
    modified = "2019-07-19"

    description = "RAT.MSIL.QuasarRAT"
    reference = "https://github.com/quasar/QuasarRAT"

    hash256 = "272d5f2ca3b139a60cd7acb616fe09e325d3046bed74e382fbb19a465a91186c"

strings:
    $gs1 = "\\firefox.exe" fullword wide
    $gs2 = "Opera Software\\Opera Stable\\Login Data" fullword wide
    $gs3 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword wide
    $gs4 = "{0}\\FileZilla\\sitemanager.xml" fullword wide
    $gs5 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" fullword wide
    $gs6 = "\\Mozilla\\Firefox\\Profiles" fullword wide

    $cmd1 = "ping -n 10 localhost > nul" fullword wide
    $cmd2 = "rmdir /q /s \"" fullword wide
    $cmd3 = "del /a /q /f \"" fullword wide
    $cmd4 = "move /y \"" fullword wide
    
    $ss1 = "DoDownloadAndExecute" fullword ascii
    $ss2 = "DoDownloadFile" fullword ascii
    $ss3 = "DoProcessKill" fullword ascii
    $ss4 = "DoShellExecute" fullword ascii
    $ss5 = "GetKeyloggerLogs" fullword ascii
    $ss6 = "get_encryptedPassword" fullword ascii
    $ss7 = "get_encryptedUsername" fullword ascii
    $ss8 = "xClient.Core.MouseKeyHook.WinApi" fullword ascii
    
condition:
    (
        (4 of ($ss*)) and (4 of ($gs*))
          or 
        (2 of ($gs*)) and (1 of ($cmd*)) and (2 of ($ss*))
    )
}
