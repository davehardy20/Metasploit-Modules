require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server - Find and Sample Data',
			'Description'    => %q{Crawl SQL Server DB Links.},
			'Author'         => [ 'Scott and Antti' ],
			'Version'        => '$Revision: 12196 $',
			'License'        => MSF_LICENSE,
			'References'     => [[ 'URL', 'http://www.netspi.com/blog/author/ssutherland/' ]],
			'Targets'        => [[ 'MSSQL 2005', { 'ver' => 2005 }]]
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
		
		# Crawl database links
		crawl_db_links(links_to_crawl,verbose)
			
	end
	
	
	##
	## Get initial data from server
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
		
		# Debugging info	
		links_to_crawl.each do |link| print_status("#{link}") end if verbose == "true"		
	
		# Return hash containing data from first db
		return links_to_crawl
	end
	
	##
	## Recursive function to crawl database links
	##
	def crawl_db_links(links_to_crawl,verbose)
	
		# Check if there are any linked servers to crawl
		
		# Set target linked server
		
		# Get data from target linked server
		
		# Add linked servers from target linked server to links_to_crawl
		
	
		# Crawl links if there are any left to crawl
		# crawl_db_links(dbs_to_crawl) if links exist
	end
	
end