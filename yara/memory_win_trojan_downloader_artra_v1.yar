rule memory_win_trojan_downloader_artra_v1
{
    meta:
        author = "raw-data"
        tlp = "WHITE"

        version = "1.0"
        created = "2019-03-26"
        modified = "2019-03-26"

        description = "Detects Artra string decryption routine"

        reference1 = "https://twitter.com/malwrhunterteam/status/1075454863008382976"
        reference2 = "https://gist.github.com/raw-data/14915eca4e5e2963a9056f935442358d"
        reference3 = "https://unit42.paloaltonetworks.com/multiple-artradownloader-variants-used-by-bitter-to-target-pakistan/"

        sha256_sample1 = "523a17f6892c2558ac4765959df4af938e56a94fa6ed39636b8b7315def3a1b4"
        sha256_sample2 = "ef0cb0a1a29bcdf2b36622f72734aec8d38326fc8f7270f78bd956e706a5fd57"

	strings:
		$hex1 = { 8a 08 40 84 c9 75 ?? 2b c2 8b f0 8d 46 01 50 e8 27 04 00 00 83 c4 04 33 c9 85 f6 7e ?? 55 8b c8  }
		$hex2 = { 8a 14 0f fe ca 88 11 41 83 ed 01 75 ?? 5d 5f c6 04 06 00  }

	condition:
		any of ($hex*)
}