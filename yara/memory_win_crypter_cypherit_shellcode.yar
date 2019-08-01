
rule memory_win_crypter_cypherit_shellcode
{

    meta:
        author = "raw-data"
        tlp = "white"

        version = "1.0"
        created = "2019-01-25"
        modified = "2019-01-25"

        description = "Detects CypherIT shellcode"
        reference = "https://raw-data.gitlab.io/post/autoit_fud/"

	strings:

        $win_api1 = { c7 8? ?? ?? ?? ?? ee 38 83 0c c7 8? ?? ?? ?? ?? 57 64 e1 01 c7 8? ?? ?? ?? ?? 18 e4 ca 08  }
        $win_api2 = { c7 8? ?? ?? ?? ?? e3 ca d8 03 c7 8? ?? ?? ?? ?? 99 b0 48 06  }

		$hashing_function = { 85 c9 74 20 0f be 07 c1 e6 04 03 f0 8b c6 25 00 00 00 f0 74 0b c1 e8 18 33 f0 81 e6 ff ff ff 0f 47 49  }

	condition:
		(1 of ($win_api*)) and $hashing_function
}