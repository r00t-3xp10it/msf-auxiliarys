# msf-auxiliarys
my collection of metasploit auxiliary post-modules

# DESCRIPTION
this working directory contains diferent metasploit auxiliary modules
writen by me to be of assistence in post-exploitation common tasks.


# INSTALL
1º - download module from github
2º - edit module and read description
3º - port module to metasploit database
4º - reload metasploit database (reload_all)

# RUNNING
1º - meterpreter > background
2º - msf exploit(handler) > use post/windows/escalate/NO-IP_privilege_escalation
3º - msf post(NO-IP_privilege_escalation) > info
4º - msf post(NO-IP_privilege_escalation) > show options
5º - msf post(NO-IP_privilege_escalation) > show advanced options
6º - msf post(NO-IP_privilege_escalation) > set [option(s)]
7º - msf post(NO-IP_privilege_escalation) > exploit
