// CredAccess

rule mem_webcreds_regexp_xor {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 reference = "https://github.com/orlyjamie/mimikittenz/blob/master/Invoke-mimikittenz.ps1"
strings:
    $p1 = "&password=" xor
	$p2 = "&login_password=" xor
	$p3 = "&pass=" xor
	$p4 = "&Passwd=" xor
	$p5 = "&PersistentCookie=" xor
	$p6 = "password%5D=" xor
	$u1 = "&username=" xor
	$u2 = "&email=" xor
	$u3 = "login=" xor
	$u4 = "login_email=" xor
	$u5 = "user%5Bemail%5D=" xor
	$reg = ".{1," xor
condition: 3 of ($p*) and 3 of ($u*) and #reg>3
}

rule webcreds_regexp_b64 {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 reference = "https://github.com/orlyjamie/mimikittenz/blob/master/Invoke-mimikittenz.ps1"
strings:
    $p1 = "&password=" base64
	$p2 = "&login_password=" base64
	$p3 = "&pass=" base64
	$p4 = "&Passwd=" base64
	$p5 = "&PersistentCookie=" base64
	$p6 = "password%5D=" base64
	$u1 = "&username=" base64
	$u2 = "&email=" base64
	$u3 = "login=" base64
	$u4 = "login_email=" base64
	$u5 = "user%5Bemail%5D=" base64
	$reg = ".{1,"
condition: 3 of ($p*) and 3 of ($u*) and #reg>3
}

rule ADSync_CredDump_Wide {
meta:
 author = "SBousseaden"
 date = "04-08-2020"
 description = "AD Connect Sync Credential Extract"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
// matches on Ghostpack ADSyncQuery.exe, ADSyncGather.exe and ADSyncDecrypt.exe
strings:
 $s1 = "private_configuration_xml" wide xor
 $s2 = "LoadKeySet" xor 
 $s3 = "encrypted_configuration" wide xor
 $s4 = "GetActiveCredentialKey" xor
 $s5 = "DecryptBase64ToString" xor
 $s6 = "KeyManager" xor
 $s7 = "(LocalDB)\\.\\ADSync" wide xor
 $s8 = "mms_management_agent" wide xor
 $s9 = "keyset_id" wide xor
 $s10 = "xp_cmdshell" xor
 $s11 = "System.Data.SqlClient"
 $s12 = "Password" wide xor
 $fp1 = "mmsutils\\mmsutils.pdb"
condition: 5 of them and not $fp1
}

rule ADSync_CredDump_Xor {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 description = "Azure AdSync Service Account Password Dumping"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $a1 = "private_configuration_xml" xor
 $a2 = "LoadKeySet" xor
 $a3 = "encrypted_configuration" xor
 $a4 = "GetActiveCredentialKey" xor
 $a5 = "DecryptBase64ToString" xor
 $a6 = "Cryptography.KeyManager" xor
 $b1 = "mms_management_agent" xor
 $b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" xor
 $b3 = "xp_cmdshell" xor
 $b4 = "Password" xor
 $b5 = "forest-login-user" xor
 $b6 = "forest-login-domain" xor
condition: 4 of ($a*) or 4 of ($b*)
}

rule ADSync_CredDump_v64 {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 description = "Azure AdSync Service Account Password Dumping"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $a1 = "private_configuration_xml" base64
 $a2 = "LoadKeySet" base64
 $a3 = "encrypted_configuration" base64
 $a4 = "GetActiveCredentialKey" base64
 $a5 = "DecryptBase64ToString" base64
 $a6 = "Cryptography.KeyManager" base64
 $b1 = "mms_management_agent" base64
 $b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" base64
 $b3 = "xp_cmdshell" base64
 $b4 = "Password" base64
 $b5 = "forest-login-user" base64
 $b6 = "forest-login-domain" base64
condition: 4 of ($a*) or 4 of ($b*)
}
rule ADSync_CredDump_XWide {
meta:
 author = "SBousseaden"
 date = "03-08-2020"
 description = "Azure AdSync Service Account Password Dumping"
 reference = "https://blog.xpnsec.com/azuread-connect-for-redteam/"
strings:
 $a1 = "private_configuration_xml" wide xor
 $a2 = "LoadKeySet" wide xor
 $a3 = "encrypted_configuration" wide xor
 $a4 = "GetActiveCredentialKey" wide xor
 $a5 = "DecryptBase64ToString" wide xor
 $a6 = "Cryptography.KeyManager" wide xor
 $b1 = "mms_management_agent" wide xor
 $b2 = "Microsoft Azure AD Sync\\Bin\\mcrypt.dl" wide xor
 $b3 = "xp_cmdshell" wide xor
 $b4 = "Password" wide xor
 $b5 = "forest-login-user" wide xor
 $b6 = "forest-login-domain" wide xor
condition: 4 of ($a*) or 4 of ($b*)
}

rule hunt_credaccess_cloud {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" xor
 $gcloud1 = "\\gcloud\\credentials.db" xor
 $gcloud2 = "\\gcloud\\legacy_credentials" xor
 $gcloud3 = "\\gcloud\\access_tokens.db" xor
 $azure1 = "\\.azure\\accessTokens.json" xor
 $azure2 = "\\.azure\\azureProfile.json" xor
 $git = "\\.config\\git\\credentials" xor // unrelated but included
 $slack1 = "\\Slack\\Cookies" xor // unrelated but included
 $slack2 = "\\Slack\\StaleCookies-8" xor // unrelated but included
condition: 4 of them
}

rule hunt_credaccess_cloud_wide_xor {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" wide xor
 $gcloud1 = "\\gcloud\\credentials.db" wide xor
 $gcloud2 = "\\gcloud\\legacy_credentials" wide xor
 $gcloud3 = "\\gcloud\\access_tokens.db" wide xor
 $azure1 = "\\.azure\\accessTokens.json" wide xor
 $azure2 = "\\.azure\\azureProfile.json" wide xor
 $git = "\\.config\\git\\credentials" wide xor // unrelated but included
 $slack1 = "\\Slack\\Cookies" wide xor // unrelated but included
 $slack2 = "\\Slack\\StaleCookies-8" wide xor // unrelated but included
condition: 4 of them
}

rule hunt_credaccess_cloud_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" base64
 $gcloud1 = "\\gcloud\\credentials.db" base64
 $gcloud2 = "\\gcloud\\legacy_credentials" base64
 $gcloud3 = "\\gcloud\\access_tokens.db" base64
 $azure1 = "\\.azure\\accessTokens.json" base64
 $azure2 = "\\.azure\\azureProfile.json" base64
 $git = "\\.config\\git\\credentials" base64 // unrelated but included
 $slack1 = "\\Slack\\Cookies" base64 // unrelated but included
 $slack2 = "\\Slack\\StaleCookies-8" base64 // unrelated but included
condition: 4 of them
}

rule hunt_credaccess_cloud_wide_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for the presence of more than 1 known cloud client utility related credential paths"
strings:
 $aws = "\\.aws\\credentials" wide base64
 $gcloud1 = "\\gcloud\\credentials.db" wide base64
 $gcloud2 = "\\gcloud\\legacy_credentials" wide base64
 $gcloud3 = "\\gcloud\\access_tokens.db" wide base64
 $azure1 = "\\.azure\\accessTokens.json" wide base64
 $azure2 = "\\.azure\\azureProfile.json" wide base64
 $git = "\\.config\\git\\credentials" wide base64 // unrelated but included
 $slack1 = "\\Slack\\Cookies" wide base64 // unrelated but included
 $slack2 = "\\Slack\\StaleCookies-8" wide base64 // unrelated but included
condition: 4 of them
}

rule hunt_credaccess_iis {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" nocase
 $a2 = "connectionStrings" nocase
 $a3 = "web.config" nocase
 $a4 = "-pdf" nocase
 $b1 = "appcmd.exe" nocase
 $b2 = "/text:password"
condition: (all of ($a*) or all of ($b*))
}

rule hunt_credaccess_iis_xor {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" wide xor
 $a2 = "connectionStrings" wide xor
 $a3 = "web.config" wide xor
 $a4 = "-pdf" wide xor
 $b1 = "appcmd.exe" wide xor
 $b2 = "/text:password" wide xor
condition: (all of ($a*) or all of ($b*))
}

rule hunt_credaccess_iis_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" base64
 $a2 = "connectionStrings" base64
 $a3 = "web.config" base64
 $a4 = "-pdf" base64
 $b1 = "appcmd.exe" base64
 $b2 = "/text:password" base64
condition: (3 of ($a*) or all of ($b*))
}

rule hunt_credaccess_iis_wide_base64 {
meta:
 author = "SBousseaden"
 date = "20-07-2020"
 description = "hunt for strings related to iis credential access"
strings:
 $a1 = "aspnet_regiis.exe" wide base64
 $a2 = "connectionStrings" wide base64
 $a3 = "web.config" wide base64
 $a4 = "-pdf" wide base64
 $b1 = "appcmd.exe" wide base64
 $b2 = "/text:password" wide base64
condition: (3 of ($a*) or all of ($b*))
}

rule hunt_TeamViewer_registry_pwddump {
meta:
 author = "SBousseaden"
 date = "23-07-2020"
 description = "cve-2019-18988 - decryption of AES 128 bits encrypted TV config pwds saved in TV registry hive"
 references = "https://community.teamviewer.com/t5/Announcements/Specification-on-CVE-2019-18988/td-p/82264"
strings:
 // hardcoded key and iv in TeamViewer_Service.exe
 $key1 = {0602000000a400005253413100040000}
 $key2 = "\\x06\\x02\\x00\\x00\\x00\\xa4\\x00\\x00\\x52\\x53\\x41\\x31\\x00\\x04\\x00\\x00"
 $iv1 = {0100010067244F436E6762F25EA8D704}
 $iv2 = "\\x01\\x00\\x01\\x00\\x67\\x24\\x4F\\x43\\x6E\\x67\\x62\\xF2\\x5E\\xA8\\xD7\\x04"
 // interesting TV regvalues are OptionsPasswordAES, ProxyPasswordAES and PermanentPassword stroed under SOFTWARE\WOW6432Node\TeamViewer or SOFTWARE\TeamViewer
 $p1 = "OptionsPasswordAES" nocase
 $p2 = "OptionsPasswordAES" nocase wide
 $p3 = "ProxyPasswordAES" nocase 
 $p4 = "ProxyPasswordAES" nocase wide
 $p5 = "PermanentPassword" nocase
 $p6 = "PermanentPassword" nocase wide
condition: any of ($key*) and any of ($iv*) and 2 of ($p*)  and filesize <700KB
}