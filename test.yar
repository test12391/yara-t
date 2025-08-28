rule CobaltStrike_Test
{
	meta:
        id = "gzIxctaiGZf4jXkwWO0BE"
        fingerprint = "ab5c7c5ea9d7d0587e8b2b327c138b2ba21ad6fbbef63f67935dab60f116088e"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:AMBER"
        source = "test"
        author = "@test"
        description = "Identifies Avaddon ransomware."
        category = "MALWARE"
        malware = "AVADDON"
        malware_type = "RANSOMWARE"
        mitre_att = "S0640"
	strings:
		$core_sig = {
      C6 44 24 48 56
      C6 44 24 49 69

      C6 44 24 4A 72

      C6 44 24 4B 74

      C6 44 24 4C 75

      C6 44 24 4D 61

      C6 44 24 4E 6C

      C6 44 24 4F 41

      C6 44 24 50 6C

      C6 44 24 51 6C

      C6 44 24 52 6F

      C6 44 24 53 63

      C6 44 24 54 00
    }
		$deobfuscator = {
      8B 04 24
      FF C0
      89 04 24
      8B 44 24 28
      39 04 24
      73 20
      8B 04 24
      0F B6 4C 24 30
      48 8B 54 24 20
      0F BE 04 02
      33 C1
      8B 0C 24
      48 8B 54 24 20
      88 04 0A
    }

	condition:
		all of them
}


rule HKTL_Win_CobaltStrike : Commodity
{
	meta:
        id = "gzIxctaiGZf4jXkwWO0BE"
        fingerprint = "ab5c7c5ea9d7d0587e8b2b327c138b2ba21ad6fbbef63f67935dab60f116088e"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:RED"
        source = "test"
        author = "@test"
        description = "Identifies Avaddon ransomware."
        category = "MALWARE"
        malware = "AVADDON"
        malware_type = "RANSOMWARE"
        mitre_att = "S0640"

	strings:
		$s1 = "%s (admin)" fullword
		$s2 = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 6F 63 74 65 74 2D 73 74 72 65 61 6D 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A 0D 0A 00}
		$s3 = "%02d/%02d/%02d %02d:%02d:%02d" fullword
		$s4 = "%s as %s\\%s: %d" fullword
		$s5 = "%s&%s=%s" fullword
		$s6 = "rijndael" fullword
		$s7 = "(null)"

	condition:
		all of them
}
