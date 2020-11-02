rule warzone rat : rat
{
	meta:
		description = "Rule that detects Warzone RAT ASCII Strings"
		threat_level = 3
		in_the_wild = true
	
	strings:
	
		$a = "warzone160" wide ascii
		$b = "AVE_MARIA" wide ascii
		$c = "WM_DSP" wide ascii
		$d = "WM_DISP" wide ascii
		
	condition:
		
		$a or $b or $c or $d
		
}		