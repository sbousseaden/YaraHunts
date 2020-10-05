rule APT_XDSSpy_XDUpload {
meta:
 author = "SBousseaden"
 date = "05/10/2020"
 reference = "https://www.welivesecurity.com/2020/10/02/xdspy-stealing-government-secrets-since-2011/"
strings:
 $s1 = "cmd.exe /u /c cd /d \"%s\" & dir /a /-c" wide
 $s2 = "commandC_dll.dll"
 $s3 = "cmd.exe /u /c del" wide
condition: uint16(0)==0x5a4d and 2 of ($s*)
}