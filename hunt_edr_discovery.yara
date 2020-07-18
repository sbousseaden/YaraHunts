rule hunt_multi_EDR_discovery {
meta:
 description = "Hunting rule for the presence of at least 3 different known EDR driver names, more drivers can be found in the reference link"
 author = "SBousseaden"
 date = "17/07/2020"
 reference = "https://github.com/harleyQu1nn/AggressorScripts/blob/master/EDR.cna"

strings:
// base64 encoded
 $edrB1 = "cbstream.sys" base64  // Carbon Black
 $edrB2 = "carbonblackk.sys" base64  // Carbon Black
 $edrB3 = "CyOptics.sys" base64  // Cylance
 $edrB4 = "CyProtectDrv32.sys" base64   // Cylance
 $edrB5 = "CyProtectDrv64.sys" base64  // Cylance
 $edrB6 = "FeKern.sys" base64  // Fireeye
 $edrB7 = "WFP_MRT.sys" base64  // Fireeye
 $edrB8 = "edevmon.sys" base64  // ESET
 $edrB9 = "ehdrv.sys" base64  // ESET
 $edrB10 = "esensor.sys" base64  // Endgame 
 $edrB11 = "SentinelMonitor.sys" base64  // SentinelOne
 $edrB12 = "groundling32.sys" base64  // Dell SecureWorks
 $edrB13 = "groundling64.sys" base64  // Dell SecureWorks
 $edrB14 = "CRExecPrev.sys" base64  // CyberReason
 $edrB15 = "brfilter.sys" base64  // Bromium
 $edrB16 = "BrCow_x_x_x_x.sys" base64  // Bromium
 $edrB17 = "fsatp.sys" base64  // F-secure
 $edrB18 = "fsgk.sys" base64  // F-secure
 $edrB19 = "CiscoAMPCEFWDriver.sys" base64  // Cisco AMP
 $edrB20 = "CiscoAMPHeurDriver.sys" base64  // Cisco
 // base64 on wide
 // base64 encoded
 $edrBW1 = "cbstream.sys" base64 wide // Carbon Black
 $edrBW2 = "carbonblackk.sys" base64 wide // Carbon Black
 $edrBW3 = "CyOptics.sys" base64 wide // Cylance
 $edrBW4 = "CyProtectDrv32.sys" base64 wide  // Cylance
 $edrBW5 = "CyProtectDrv64.sys" base64 wide // Cylance
 $edrBW6 = "FeKern.sys" base64 wide // Fireeye
 $edrBW7 = "WFP_MRT.sys" base64 wide // Fireeye
 $edrBW8 = "edevmon.sys" base64 wide // ESET
 $edrBW9 = "ehdrv.sys" base64 wide // ESET
 $edrBW10 = "esensor.sys" base64 wide // Endgame 
 $edrBW11 = "SentinelMonitor.sys" base64 wide // SentinelOne
 $edrBW12 = "groundling32.sys" base64 wide // Dell SecureWorks
 $edrBW13 = "groundling64.sys" base64 wide // Dell SecureWorks
 $edrBW14 = "CRExecPrev.sys" base64 wide // CyberReason
 $edrBW15 = "brfilter.sys" base64 wide // Bromium
 $edrBW16 = "BrCow_x_x_x_x.sys" base64 wide // Bromium
 $edrBW17 = "fsatp.sys" base64 wide // F-secure
 $edrBW18 = "fsgk.sys" base64 wide // F-secure
 $edrBW19 = "CiscoAMPCEFWDriver.sys" base64 wide // Cisco AMP
 $edrBW20 = "CiscoAMPHeurDriver.sys" base64 wide // Cisco
// XORed
 $edrX1 = "cbstream.sys" xor // Carbon Black
 $edrX2 = "carbonblackk.sys" xor // Carbon Black
 $edrX3 = "CyOptics.sys" xor // Cylance
 $edrX4 = "CyProtectDrv32.sys" xor  // Cylance
 $edrX5 = "CyProtectDrv64.sys" xor // Cylance
 $edrX6 = "FeKern.sys" xor // Fireeye
 $edrX7 = "WFP_MRT.sys" xor // Fireeye
 $edrX8 = "edevmon.sys" xor // ESET
 $edrX9 = "ehdrv.sys" xor // ESET
 $edrX10 = "esensor.sys" xor // Endgame 
 $edrX11 = "SentinelMonitor.sys" xor // SentinelOne
 $edrX12 = "groundling32.sys" xor // Dell SecureWorks
 $edrX13 = "groundling64.sys" xor // Dell SecureWorks
 $edrX14 = "CRExecPrev.sys" xor // CyberReason
 $edrX15 = "brfilter.sys" xor // Bromium
 $edrX16 = "BrCow_x_x_x_x.sys" xor // Bromium
 $edrX17 = "fsatp.sys" xor // F-secure
 $edrX18 = "fsgk.sys" xor // F-secure
 $edrX19 = "CiscoAMPCEFWDriver.sys" xor // Cisco AMP
 $edrX20 = "CiscoAMPHeurDriver.sys" xor // Cisco
// XOR on wide 
 $edrXW1 = "cbstream.sys" xor wide // Carbon Black
 $edrXW2 = "carbonblackk.sys" xor wide // Carbon Black
 $edrXW3 = "CyOptics.sys" xor wide // Cylance
 $edrXW4 = "CyProtectDrv32.sys" xor wide  // Cylance
 $edrXW5 = "CyProtectDrv64.sys" xor wide // Cylance
 $edrXW6 = "FeKern.sys" xor wide // Fireeye
 $edrXW7 = "WFP_MRT.sys" xor wide // Fireeye
 $edrXW8 = "edevmon.sys" xor wide // ESET
 $edrXW9 = "ehdrv.sys" xor wide // ESET
 $edrXW10 = "esensor.sys" xor wide // Endgame 
 $edrXW11 = "SentinelMonitor.sys" xor wide // SentinelOne
 $edrXW12 = "groundling32.sys" xor wide // Dell SecureWorks
 $edrXW13 = "groundling64.sys" xor wide // Dell SecureWorks
 $edrXW14 = "CRExecPrev.sys" xor wide // CyberReason
 $edrXW15 = "brfilter.sys" xor wide // Bromium
 $edrXW16 = "BrCow_x_x_x_x.sys" xor wide // Bromium
 $edrXW17 = "fsatp.sys" xor wide // F-secure
 $edrXW18 = "fsgk.sys" xor wide // F-secure
 $edrXW19 = "CiscoAMPCEFWDriver.sys" xor wide // Cisco AMP
 $edrXW20 = "CiscoAMPHeurDriver.sys" xor wide // Cisco
condition: 3 of them
}