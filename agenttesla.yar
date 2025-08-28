rule windows_agenttesla_Trojan_v0_250103103800
{
meta:
    mwcp = "AgentTesla"
    description = "AgentTesla payload"
    confidence = 90
    severity = "critical"
    level = "attack"
    version = "1.0"
    threat_name = "AgentTesla"
    hash = "14b59418593e4def07b6ba58cb362885337d9605d843448dc6b2037962a3b65d"
    refrule = ""
    refproduct = ""
    auditor = "gzh"
    scene = "detection"
    matching = "all"
    source = "tb_analyst_sampleanalysis"
    team = "000"
    category = "默认分类"//规则分类，由各业务组分别定义，从规则集继承，平台自动填写。
    author = "gongzihao"//创建人，平台自动填写
    created = "2024/12/25"//规则创建日期，平台自动填写
    editor = "gongzihao"//最后编辑人，平台自动填写
    updated = "2024/12/25"//规则更新日期，平台自动填写
    version_code = 1//规则版本号，平台自动填写

strings:
    $a1 = "MozillaBrowserList"
    $a2 = "EnableScreenLogger"
    $a3 = "VaultGetItem_WIN7"
    $a4 = "PublicIpAddressGrab"
    $a5 = "EnableTorPanel"
    $a6 = "get_GuidMasterKey"
    $s1 = "\\\"(hostname|encryptedPassword|encryptedUsername)\":\"(.*?)\"" fullword wide
    $s2 = "\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide
    $s3 = "\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
    $s4 = "\\Trillian\\users\\global\\accounts.dat" fullword wide
    $s5 = "\\VirtualStore\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" fullword wide
    $s6 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" fullword wide
    $s7 = "CheckTorProcess" fullword ascii
    $s8 = "FtpPassword" fullword ascii
    $s9 = "get_AccountConfiguration" fullword ascii
    $s10 = "get_AccountCredentialsModel" fullword ascii
    $s11 = "get_BindingAccountConfiguration" fullword ascii
    $s12 = "get_passwordIsSet" fullword ascii
    $s13 = "get_templatePresets" fullword ascii
    $s14 = "http://ip-api.com/line/?fields=hosting" fullword wide
    $s15 = "KillTorProcess" fullword ascii
    $s16 = "passwordIet_version" fullword ascii
    $s17 = "SMTP Password" fullword wide
    $s18 = "SmtpAccountConfiguration" fullword ascii
    $s19 = "SmtpPassword" fullword wide

condition:
    5 of them and
    uint16(0) == 0x5a4d and filesize < 20MB

}
