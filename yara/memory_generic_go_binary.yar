rule memory_generic_go_binary
{
  meta:
    author = "raw-data"
    tlp = "WHITE"

    version = "2.0"
    created = "2019-03-13"
    modified = "2019-03-13"

    description = "Track binaries written in Golang"

  strings:
    $x1 = "golang.org/x/crypto/ssh" fullword ascii
    $x2 = "golang_org/x/net/http2" fullword ascii
    $x3 = "go/src/net/dnsclient.go" fullword ascii
    $x4 = "_cgo_panic" fullword ascii
    $x5 = "_cgo_topofstack" fullword ascii
    $x6 = "_cgo_allocate" fullword ascii
    $x7 = "_cgo_reginit" fullword ascii

    $hex1 = {67 6f 2d 62 75 69 6c 64} // go-build
    $hex2 = {47 6f 20 62 75 69 6c 64 20 49 44} // Go build ID
    $hex3 = {73 79 73 63 61 6c 6c 2e} // syscall.
    $hex4 = {67 6f 6c 61 6e 67 5f 6f 72 67} // golang_org
    $hex5 = {63 72 79 70 74 6f 2f 74 6c 73 2e} // crypto/tls.
    $hex6 = {2f 67 6f 2f 73 72 63 2f} // /go/src/
    $hex7 = {67 6f 2d 71 75 65 72 79 73 74 72 69 6e 67} //go-querystring

  condition:
    3 of them
}