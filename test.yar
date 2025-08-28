rule HKTL_T : Commodity
{
	meta:
        sharing = "TLP:WHITE"
        category = "TOOL"
	strings:
		$s1 = "PE"

	condition:
		all of them
}
