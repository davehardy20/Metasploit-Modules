##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather Domain User Sessions',
			'Description'   => %q{
				This module enumerates active domain user sessions.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Scott Sutherland <scott.sutherland[at]nullbind.com>'],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
		
		register_options(
			[
				OptString.new('DOMAIN',  [false, 'Domain to target, default to computer\'s domain', '']),
				OptString.new('TYPE',  [true, 'Search type: GROUPS or USERS', 'GROUPS']),
				OptString.new('GROUP',  [false, 'Domain groups to search for.', 'Domain Admins, Forrest Admins, Enterprise Admins']),
				OptString.new('USER',  [false, 'Domain users to search for.', '']),
				OptBool.new('LOOP',  [false, 'Scan for sessions continuously', 'false']),
			], self.class
		)
		
	end

	def run
	
		#Create an array to hold the list of domains
		#Create an array to hold the domain controller IP addresses
		#Create an array to hold the session information login,domain,ip,idle time,session time
		#Create an array to hold the group information login,domain
		#Create an array to hold final list domain, group, user, ip
	
		#Get current domain or set it from the option
	
		#Get a list of all of the domains in the forrest
		# adfind -sc domainlist 
		
		#Get a list of trust for the current domain
		# adfind -sc trustdmp
		
		#Get a list of the domain controllers for the current domain
		# adfind -sc dclist
		# add to the domain controllers array
		
		#Get a list of the domain controllers for the trusted domains
		# adfind -b dc=trusted,dc=otherdomain,dc=domainname,dc=com -sc
		# add to the domain controllers array
		
		#For each domain controller grab the active sessions add add to a
		
		# Most of the code below is from Mubix's enum_domains module
		
		buffersize = 500
		result = client.railgun.netapi32.NetSessionEnum(nil,nil,nil,10,4,buffersize,4,4,nil)
		print_status("Finding the right buffersize...")
		while result['return'] == 234
			print_status("Tested #{buffersize}, got #{result['entriesread']} of #{result['totalentries']}")
			buffersize = buffersize + 500
			result = client.railgun.netapi32.NetSessionEnum(nil,nil,nil,10,4,buffersize,4,4,nil)
		end

		count = result['totalentries']
		print_status("#{count} Sessions found.")
		startmem = result['bufptr']

		base = 0
		mysessions = []
		mem = client.railgun.memread(startmem, 8*count)
		count.times{|i|
			x = {}
			x[:a] = mem[(base + 0),4].unpack("V*")[0]
			nameptr = mem[(base + 4),4].unpack("V*")[0]
			x[:b] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
			mysessions << x
			base = base + 8
		}
		puts mysessions.inspect
		
	end
end
