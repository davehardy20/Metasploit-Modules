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

	def print_with_underline(str)
		print_line(str)
		print_line("=" * str.length)
	end

	def run_host(ip)
		
		# Set verbosity
		verbose = datastore['verbose'].to_s.downcase 
		
		# Setup first server
		links_to_crawl = getstartdata(verbose)
		
		# Debugging information
		print_status("Hash exported by first method:") if verbose == "true"
		links_to_crawl.each do |link| print_status("#{link}") end if verbose == "true"	
		
		# Crawl database links
		crawl_db_links(links_to_crawl,verbose)
			
	end
	
	
	##
	## Method of getting initial data from target SQL Server
	##
	def getstartdata(verbose)
	
		# CREAT ARRAY TO STORE DB SERVER HASH
		links_to_crawl= Array.new 	#LINKS TO CRAWL
			
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
		result = mssql_query(sql, false) if mssql_login_datastore
		column_data = result[:rows]
		
		## PROCESS QUERY RESULTS
		column_data.each {|server,sysadmin,version,linkpath|			

			## ADD FIRST SERVER HASH TO THE links_to_crawlARRAY TO KICK OFF THE DBLINK CRAWLER
			dbtarget = Hash['server'=>"#{server}",'sysadmin'=>"#{sysadmin}",'version'=>"#{version}",'linkpath'=>"",'parent'=>""]
			links_to_crawl<< dbtarget				
		}
		disconnect
		
		# Debugging information	
		print_status("Hash defined in first method for initial target:") if verbose == "true"
		links_to_crawl.each do |link| print_status("#{link}") end if verbose == "true"		
	
		# Return hash containing data from first db
		return links_to_crawl
	end
	
	##
	## Method (recursive) for crawling database links
	##
	def crawl_db_links(links_to_crawl,verbose)
		
		# Debugging information
		print_status("Hash imported to recursive function from first method:") if verbose == "true"
		links_to_crawl.each do |link| print_status("#{link}") end if verbose == "true"	
	
		# Check if there are any linked servers to crawl
		if links_to_crawl.empty?.to_s == "true" then
			print_status("No more database links to crawl")
		else
			print_status("Attempting to crawl database links...")
			
			# Iterate through each hash
			
				# Set path seperator character
				
				# Set target server/path to be processed
				
				# Get link depth for target server, if not set	
				
				# Setup number of ticks for openquery nesting
				
				# Setup inside query to get data from target server	
				
				# Generate left side of query
				
				# Generate right side of query

				# Generate full query to be executed
				
				# Connect to initial database entry point and execute query
				
					# Get list of links, for each link
						
						# If link does not exist in links_to_crawl or links_crawled then
						
							# Add link to links_to_crawl if it does not exist
							
							#Update link hash info using data from sql query 
				
				# Remove current target from links_to_crawl

			# crawl_db_links(links_to_crawl) if links_to_crawl is not empty
		end
	end
	
end