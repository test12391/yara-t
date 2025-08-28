rule CobaltStrike_Sleeve_BeaconLoader_VA_x64_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
        id = "gzIxctaiGZf4jXkwWO0BE"
        fingerprint = "ab5c7c5ea9d7d0587e8b2b327c138b2ba21ad6fbbef63f67935dab60f116088e"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
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
