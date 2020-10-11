import "pe"
rule GOSilver {
meta:
 author = "SBousseaden"
 reference = "https://github.com/BishopFox/sliver"
strings:
 $go = "_cgo_"
condition: #go > 10 and pe.exports("RunSliver")
}