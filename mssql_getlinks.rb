require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server - Crawl Database Server Links',
			'Description'    => %q{This will crawl SQL Server database links with provide 
			provide credentials.},
			'Author'        => [ 'Scott Sutherland <scott.sutherland@netspi.com>'],
			'Platform'      => [ 'Windows' ],
			'License'        => MSF_LICENSE,
			'References'     => [[ 'URL', 'http://www.netspi.com/blog/author/ssutherland/' ]],
		))

		register_options(
			[	
				OptBool.new('VERBOSE',  [false, 'Set how verbose the output should be', 'false']),				
			], self.class)
	end
	
	def run_host(ip)
		
		# Set verbosity
		verbose = datastore['verbose'].to_s.downcase 
		
		# Create primary arrays
		links_to_crawl= Array.new 	
		links_crawled= Array.new 	
		
		# Setup first server
		links_to_crawl = getstartdata(ip,links_to_crawl,verbose)
		
		# Debugging information
		print_status("Hash exported by first method:") if verbose == "true"
		links_to_crawl.each do |link| print_status("#{link}") end if verbose == "true"	
		
		# Crawl database links
		crawl_db_links(links_to_crawl,links_crawled,verbose)
		
		# Report high level findings
		print_status("---------------------------------------------------------------")
		print_status("SQL servers crawled: #{links_crawled.count}")
		print_status("SQL sysadmin links: PENDING")
		print_status("---------------------------------------------------------------")
			
	end
	
	
	##
	## Method of getting initial data from target SQL Server
	##
	def getstartdata(ip,links_to_crawl,verbose)
		
		# GET INFORMATION FROM CURRENT DATABASE
		# SETUP QUERY
		sql = "SELECT @@servername as server,
			(select is_srvrolemember('sysadmin')) as sysadmin,
			(REPLACE(REPLACE(REPLACE(ltrim((select REPLACE((Left(@@Version,CHARINDEX('-',@@version)-1)),'Microsoft','')+ 
			rtrim(CONVERT(char(30), SERVERPROPERTY('Edition'))) +' '+ 
			RTRIM(CONVERT(char(20), SERVERPROPERTY('ProductLevel')))+ 
			CHAR(10))), CHAR(10), ''), CHAR(13), ''), CHAR(9), '')) as version,
			@@servername as linkpath"
		
		##	EXECUTE QUERY
		print_status("Attempting to obtain data from SQL Server at '#{ip}'...")
		result = mssql_query(sql, false) if mssql_login_datastore
		column_data = result[:rows]
		
		## PROCESS QUERY RESULTS
		column_data.each {|server,sysadmin,version,linkpath|			

			## ADD FIRST SERVER HASH TO THE links_to_crawlARRAY TO KICK OFF THE DBLINK CRAWLER
			dbtarget = Hash['server'=>"#{server}",'sysadmin'=>"#{sysadmin}",'version'=>"#{version}",'linkpath'=>"",'parent'=>""]
			links_to_crawl<< dbtarget				
		}
		disconnect
		
		print_good("Successfully obtained data from SQL Server at '#{ip}'...")
		
		# Debugging information	
		print_status("Hash defined in first method for initial target:") if verbose == "true"
		links_to_crawl.each do |link| print_status("#{link}") end if verbose == "true"		
	
		# Return hash containing data from first db
		return links_to_crawl
	end
	
	
	##
	## Method for crawling database links
	##
	def crawl_db_links(links_to_crawl,links_crawled,verbose)
		
		# Debugging information
		#print_status("Hash imported to recursive function from first method:") if verbose == "true"
		#links_to_crawl.each do |link| print_status("#{link}") end if verbose == "true"	
	
		# Check if there are any linked servers to crawl
		if links_to_crawl.empty?.to_s == "true" then
			print_status("No more database links to crawl")
		else					
			
			# Iterate through each hash
			links_to_crawl.map {|dbsrv_hash| 						
				
				# Statusing
				print_status("---------------------------------------------------------------")
				print_status("Searching for linked servers on #{dbsrv_hash['server']}...")
				print_status("Target hash: #{dbsrv_hash['server']} : #{dbsrv_hash['sysadmin']} : #{dbsrv_hash['version']} : #{dbsrv_hash['linkpath']} : #{dbsrv_hash['parent']}")				
				
				# Set target server/path to be processed
				oserver_path = dbsrv_hash['linkpath']
				
				# Set delim character
				mydelim = ">"
				
				# Set path seperator character
				oserver_pathdelim = " #{mydelim} " if oserver_path > ""
				
				# Get link depth for target server, if not set	- fix this
				current_linkpath = dbsrv_hash['linkpath'].split(" > ")
				current_linkdepth = dbsrv_hash['linkpath'].scan(/>/).count
				print_status("Link path depth: #{current_linkdepth}")	
				
				# Setup number of ticks for openquery nesting
				sql_right = ''
				sql_left = ''		
				thecount = 0 #use for generating ticks				
				
				# Setup inside query to get data from target server	
				sql_center = "SELECT @@servername as server,
					(select is_srvrolemember('sysadmin')) as sysadmin,
					(REPLACE(REPLACE(REPLACE(ltrim((select REPLACE((Left(@@Version,CHARINDEX('-',@@version)-1)),'Microsoft','')+ 
					rtrim(CONVERT(char(30), SERVERPROPERTY('Edition'))) +' '+ 
					RTRIM(CONVERT(char(20), SERVERPROPERTY('ProductLevel')))+ 
					CHAR(10))), CHAR(10), ''), CHAR(13), ''), CHAR(9), '')) as version,
					'#{oserver_path}'+'#{oserver_pathdelim}'+@@Servername+' > '+srvname as linkpath
					FROM master..sysservers 
					WHERE 
					srvname not like @@SERVERNAME and 
					providername = 'SQLOLEDB' and 
					dataaccess = '1'"
				
				# Create the sql statement based on link depth
				if current_linkdepth > 0
				
					#create left side - create open query on left side
					current_linkpath.shift #Get rid of entry point for loop
					print_status("Current link path: \n #{current_linkpath}")
					
					current_linkpath.each {|link|
							thecount = thecount + 1
							ticks = "'" * (thecount * thecount)
							sql_left << "select server,sysadmin,version,linkpath from openquery(\"#{dbsrv_hash['server']}\",#{ticks}"										
					}
					
					#create right side - create where filter statements on right side
					current_linkpath.each {|link|	
							ticks = "'" * (thecount * 2)
							sql_right << "#{ticks}\")"										
					}
					
					#Build final query from sql_right, sql_left, and sql_center
					sql = "#{sql_left} #{sql_center} #{sql_right}"
					
				else
					sql = "
					SELECT
					srvname,
					'unknown',
					'unknown',
					'#{oserver_path}'+'#{oserver_pathdelim}'+@@Servername+' > '+srvname 
					FROM master..sysservers 
					WHERE 
					srvname not like @@SERVERNAME and 
					providername = 'SQLOLEDB' and 
					dataaccess = '1'"
				end
										
				
				print_status("QUERY:\n #{sql}")
				
				
				##
				## Connect to database and process query target server
				##
				result = mssql_query(sql, false) if mssql_login_datastore
				column_data = result[:rows]
						
				print_status("sql results: #{column_data}")	
				
				#Process each link on the target server
				column_data.each {|server,sysadmin,version,linkpath|
						
					# Print information for newly identified  link 
					print_good("FOUND LINK: #{server} : unknown : unknown : #{linkpath} : #{dbsrv_hash['server']}")
							
					# Build hash record for link
					addthislink = Hash['server'=>"#{server}",'sysadmin'=>'unknown','version'=>'unknown','linkpath'=>"#{linkpath}",'parent'=>"#{dbsrv_hash['server']}"]
							
					# Add to link_to_crawl queue
					links_to_crawl << addthislink															
																
				}										
				disconnect							
				
				# Add current target server to links_crawled
				temp_hash = Hash['server'=>"#{dbsrv_hash['server']}",'sysadmin'=>"#{dbsrv_hash['sysadmin']}",'version'=>"#{dbsrv_hash['version']}",'linkpath'=>"#{dbsrv_hash['linkpath']}",'parent'=>"#{dbsrv_hash['parent']}"]
				links_crawled << temp_hash
				
				# Debugging information	
				print_status("crawled links:") if verbose == "true"
				links_crawled.each do |link| print_status("link: #{link}") end if verbose == "true"	
				
				# Remove current target server from links_to_crawl
				if links_to_crawl.include? temp_hash then
					print_status("Current hash target found in links_to_crawl!") if verbose == "true"
					killindex = links_to_crawl.index(temp_hash)	
					killindex = links_to_crawl.index(temp_hash)	
					links_to_crawl.delete_at(killindex)
					
				else
					print_status("not there!")
				end
				
				# Continue to crawl if links_to_crawl array is not empty
				if links_to_crawl.empty? then 
					print_status("No more links to crawl")
				else
					# Debugging information	
					print_status("Links left to crawl:") if verbose == "true"
					links_to_crawl.each do |link| print_status("link: #{link}") end if verbose == "true"
					
					# add call to recusive funciton here
					crawl_db_links(links_to_crawl,links_crawled,verbose)
				end
			}		
		end		
	end	
end