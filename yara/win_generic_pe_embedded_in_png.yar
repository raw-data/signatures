rule win_generic_pe_embedded_in_png
{

    meta:
        author = "raw-data"
        tlp = "white"

        version = "1.0"
        created = "2019-04-25"
        modified = "2019-04-25"

        description = "Detects a PE Windows executable embedded in a PNG file"

    strings:

        $png_header = {89 50 4E 47} //PNG
        $png1 = {49 48 44 52} // IHDR
        $png2 = {73 52 47 42} //sRGB
        $png3 = {67 41 4D 41} // gAMA
        $png4 = {70 48 59 73} // pHYs
        $png5 = {49 44 41 54 78} //IDATx
        $png_footer = {00 49 45 4E 44 AE 42} //.IEND_B

        $mz = {4d 5a}
        $pe = {50 45}
        $dos = {54 68 69 73 20 70 72 6F 67 72 61 6D 20}

  condition:
    (
        ( $png_header at 0 and (1 of ($png*)) and $png_footer)
            and
        ($mz and ($pe or $dos))
    )
}
