rule PowerShellSuspiciousStrings
{
    meta:
        /* originally by */
        author = "Xavier Mertens (@xme)"
        /* expanded by */
        author = "raw-data"
        tlp = "WHITE"

        version = "1.0"
        created = "2018-11-07"
        modified = "2018-11-07"

        description = "PowerShellSuspiciousStrings"
        /* origianlly from */
        reference = "https://isc.sans.edu/forums/diary/Malicious+Powershell+Script+Dissection/24282/"

    strings:

        $ps1 = "powershell" nocase wide ascii
        $ps2 = "IEX" nocase wide ascii
        $ps3 = "new-object" nocase wide ascii
        $ps4 = "webclient" nocase wide ascii
        $ps5 = "downloadstring" nocase wide ascii
        $ps6 = "Hidden" nocase wide ascii
        $ps7 = "invoke" nocase wide ascii
        $ps8 = "Get-Random -input" nocase wide ascii
        $ps9 = "bypass" nocase wide ascii
        $ps10 = "shellcode" nocase wide ascii
        $ps11 = "Enter-PSSession" nocase wide ascii
        $ps12 = "-NoP" nocase wide ascii
        $ps13 = "-Enc" nocase wide ascii
        $ps14 = "-NonI" nocase wide ascii
        $ps15 = "downloadfile" nocase wide ascii
        $ps16 = "Invoke-Expression" nocase wide ascii
        $ps17 = "Start-Process" nocase wide ascii
        $ps18 = "ShellExecute" nocase wide ascii
        $ps19 = "[System.Convert]::" nocase wide ascii
        $ps20 = "FromBase64String(" nocase wide ascii
        $ps21 = "New-Object System.IO." nocase wide ascii
        $ps22 = "[System.Net." nocase wide ascii
        $ps23 = "System.Reflection.AssemblyName" nocase wide ascii
        $ps24 = "cG93ZXJzaGVsbC" nocase wide ascii
        $ps25 = "UG93ZXJTaGVsbC" nocase wide ascii

        $ps26 = "[System.Environment]::OSVersion.Version" nocase wide ascii
        $ps27 = "APPDATA" nocase wide ascii
        $ps28 = "WebRequest" nocase wide ascii
        $ps29 = "WriteAllBytes" nocase wide ascii
        $ps30 = "[IO.File]" nocase wide ascii
        $ps31 = "[Convert]::" nocase wide ascii
        $ps32 = "Get-Random -Minimum" nocase wide ascii
        $ps33 = "Get-Random -Count" nocase wide ascii
        $ps34 = "New-ItemProperty" nocase wide ascii
        $ps35 = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RUN" nocase wide ascii
        $ps36 = "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" nocase wide ascii
        $ps37 = "Start-Sleep" nocase wide ascii
        $ps38 = "Invoke-WebRequest" nocase wide ascii

    condition:
        5 of them
}
