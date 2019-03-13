rule memory_generic_office_macro_xlcountrysetting
{
    meta:
        author = "raw-data"
        tlp = "WHITE"

        version = "1.0"
        created = "2019-03-12"
        modified = "2019-03-12"

        description = "Office Macro checking xlCountrySetting"

        reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/from-fileless-techniques-to-using-steganography-examining-powloads-evolution/"

        sha256_sample1 = "23e85ee19a2f46f4f462e72995b6a91616ea2f315908c1566c36cd0afc3aa200"
        sha256_sample2 = "667e30b20e0986c7def59f66d871a579a32f150b61f64aefd431864b33dced12"
    
    strings:
        
        $file_header1 = {D0 CF 11 E0} // xls, doc and ppt header DOC, PPT, XLS
        $file_header2 = {50 4B 03 04} // xlsx, docx and pptx header
        $file_header3 = {4D 49 4D 45} // MIME header

        $gs1 = "Macros" wide fullword
        $gs2 = "QWN0aXZlTWltZQA" ascii fullword // base64("ActiveMime")
        $gs3 = "AutoOpen" ascii fullword
        $gs4 = "Workbook_Open" ascii fullword
        $gs5 = "_VBA_PROJECT_CUR" wide fullword

        $hexss1 = {78 6c 43 6f 75 6e 74 72 79 53 65 74 74 69 6e 67} // xlCountrySetting
        $hexss2 = {65 47 78 44 62 33 56 75 64 48 4a 35 55 32 56 30 64 47 6c 75 5a 77} // hex(base64("xlCountrySetting"))

    condition:
        (
            (1 of ($file_header*)) and (1 of ($gs*)) and (1 of ($hexss*))
                or
            (1 of ($file_header*)) and (1 of ($hexss*))
        )
}