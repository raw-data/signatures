rule memory_win_generic_nsis_installer
{

    meta:
        author = "raw-data"
        tlp = "white"

        version = "1.0"
        created = "2019-04-25"
        modified = "2019-04-25"

        description = "Detects a MS Windows, Nullsoft Installer self-extracting archive"

    strings:

        $mz = {4d 5a}

        $ss1 = {4e 53 49 53 20 45 72 72  6f 72} // NSIS Error
        $ss2 = {4e 75 6c 6c 73 6f 66 74} // Nullsoft
        $ss3 = {6e 73 69  73 2e 73 66 2e 6e 65 74} // nsis.sf.net
 
  condition:
    (
        $mz and (2 of ($ss*))
    )
    
}