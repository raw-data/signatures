
rule memory_unix_trojan_goscanssh
{
  meta:
    author = "raw-data"
    tlp = "WHITE"

    type = "ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), stripped"
    version = "2.0"
    created = "2018-04-08"
    modified = "2019-03-13"

    description = "Trojan.Linux.GoScanSSH"
    reference = "http://blog.talosintelligence.com/2018/03/goscanssh-analysis.html"

    hash_md5 = "df1ca8e5d83a7fb940e3cbcf38e25cc9eceb9461"
    hash_md5 = "7f93c6b850f333693b69bb466d92f77182c52f61"
    hash_md5 = "e52692f1f43e670d1c4b540b93223157b94a761e"
    hash_md5 = "6b6aa7c4eb2839f18cc455fa3b3b01b3c22ba6a7"

  strings:
    $x1 = "golang.org/x/crypto/ssh" fullword ascii
    $x2 = "golang_org/x/net/http2" fullword ascii
    $x3 = "go/src/net/dnsclient.go" fullword ascii
    $x4 = "main.reverseDNS"fullword ascii

    $cnc1 = ".onion.to" fullword ascii
    $cnc2 = ".onion.cab" fullword ascii
    $cnc3 = ".onion.link" fullword ascii
    $cnc4 = ".onion.top" fullword ascii
    $cnc5 = ".onion.plus" fullword ascii
    $cnc6 = ".onion.guide" fullword ascii

    $hex_d1 = { 2E 6D 6F 64 2E 75 6B }
    $hex_d2 = { 2E 6D 69 6C 2E 7A 61 }
    $hex_d3 = { 2E 6D 69 6C 2E 75 6B }
    $hex_d4 = { 2E 6D 69 6C 2E 6E 7A }
    $hex_d5 = { 2E 69 64 66 2E 69 6C }
    $hex_d6 = { 2E 67 6F 76 2E 7A 61 }
    $hex_d7 = { 2E 67 6F 76 2E 75 6B }
    $hex_d8 = { 2E 67 6F 76 2E 69 6C }
    $hex_d9 = { 2E 67 6F 76 2E 61 75 }
    $hex_d10 = { 2E 67 6F 62 2E 65 73 }

    $hex_n1 = { 31 37 32 2E 31 36 2E 30 2E 30 2F 31 32 }
    $hex_n2 = { 31 30 30 2E 36 34 2E 30 2E 30 2F 31 30 }
    $hex_n3 = { 15 31 39 38 2E 31 38 2E 30 2E 30 2F 31 }
    $hex_n4 = { 31 36 39 2E 32 35 34 2E 30 2E 30 2F 31 36 }
    $hex_n5 = { 31 39 32 2E 38 38 2E 39 39 2E 30 2F 32 34 }
    $hex_n6 = { 31 39 38 2E 35 31 2E 31 30 30 2E 30 2F 32 34 }
    $hex_n7 = { 32 35 35 2E 32 35 35 2E 32 35 35 2E 32 35 35 2F 33 32}

  condition:
    (
            (2 of ($x*) and  3 of ($cnc*) and 4 of ($hex_d*) and 4 of ($hex_n*))
        or
            (2 of ($x*) and 5 of ($hex_d*) and 5 of ($hex_n*))
    )
}
