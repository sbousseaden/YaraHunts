import "pe" 

rule susp_winsvc_upx {
meta:
  description = "broad hunt for any PE exporting ServiceMain API and upx packed"
  author = "SBousseaden"
  date = "2019-01-28"
strings:
  $upx1 = {55505830000000}
  $upx2 = {55505831000000}
  $upx_sig = "UPX!"
condition: uint16(0)==0x5a4d and $upx1 in (0..1024) and 
 $upx2 in (0..1024) and $upx_sig in (0..1024) and pe.exports("ServiceMain") }
