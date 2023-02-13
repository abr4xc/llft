#!/bin/bash

cat << "EOF"                     
  _      _                    _      _____           ______ ____                     _            _______          _ 
 | |    (_)                  | |    |_   _|         |  ____/ __ \                   (_)          |__   __|        | |
 | |     _ _ __  _   ___  __ | |      | |_   _____  | |__ | |  | |_ __ ___ _ __  ___ _  ___ ___     | | ___   ___ | |
 | |    | | '_ \| | | \ \/ / | |      | \ \ / / _ \ |  __|| |  | | '__/ _ \ '_ \/ __| |/ __/ __|    | |/ _ \ / _ \| |
 | |____| | | | | |_| |>  <  | |____ _| |\ V /  __/ | |   | |__| | | |  __/ | | \__ \ | (__\__ \    | | (_) | (_) | |
 |______|_|_| |_|\__,_/_/\_\ |______|_____\_/ \___| |_|    \____/|_|  \___|_| |_|___/_|\___|___/    |_|\___/ \___/|_
EOF

# Get the date and time for the report
date=$(date +"%Y-%m-%d_%H-%M-%S")

# Prompt the user to enter the auditor name and case name
read -p "Enter the Investigator name: " auditor_name
read -p "Enter the case ID: " case_name
read -p "Enter the case Location: " case_location

# Get the system hostname
hostname=$(hostname)

# Create Directory
echo "Creating Report Directory"

Directory="$hostname-$date"
mkdir $Directory
mkdir $Directory/logs

# Create the output file name
output_file="$hostname-$date.html"

# Get the list of logged-in users
echo "Getting Users information"
logged_in_users=$(who)

# Get the command history for each user
echo "Getting command history"

command_history=""
for user in $(who | awk '{print $1}' | sort -u)
do
    command_history="$command_history\n<h3>Command history for user $user:</h3>\n<pre>$(history -n 1000 | grep -E '^ *[0-9]+  *' | sed -e 's/^ *[0-9][0-9]*  *//' -e 's/\n/\n/g')</pre>"
done

# Get the failed login attempts
echo "Getting login information"

failed_logins=$(grep 'authentication failure' /var/log/auth.log | tail -n 10)

# Get the login history
login_history=$(last | head -n 20)

# Find modified files from all users except system and proc
echo "Getting files information"
modified_files=$(find /home -type f ! -path "/home/*/.cache/*" ! -path "/home/*/.local/share/Trash/*" -printf '%TY-%Tm-%Td %TH:%TM:%.2TS %u %p\n' | sort -r | head -n 100)

# Get Open Files
open_files=$(lsof -V)

# Get the open network connections
echo "Getting network information"
open_connections=$(lsof -i -P -n)

# Processes and ports

net_pro=$(netstat -anp)

# Get the file access history
file_access_history=$(ausearch -ua $(id -u) -i -ts today | grep "type=SYSCALL.*exe=" | awk '{print $1" "$2" "$13" "$14}')

# Get the audit logs
audit_logs=$(ausearch -ua $(id -u) -i -ts today)

# Get suspicious processes
suspicious_processes=$(ps -eo pid,user,args --sort=-%cpu | awk '$3~/\/bin\/bash|\/usr\/bin\/python|nc|nmap|ruby|perl|lua|sh|php|wget|curl/{print $0}' | head -n 10)

# Get user account changes
user_account_changes=$(grep "useradd\|usermod\|userdel" /var/log/auth.log)

# Get users in the system
all_users_system=$(getent passwd)

# Get lastlog entries
lastlog_entries=$(lastlog | grep -v 'Never')

# Get the list of running processes
echo "Getting procesess information"
running_processes=$(ps -aux)

# Get the list of schedulte tasks
echo "Getting schedule tasks information"
schredule_task=$(for user in $(cut -f1 -d: /etc/passwd); do echo "Crontab for $user:"; crontab -u $user -l 2>/dev/null; done | grep -vE "nobody|systemd" | uniq | grep -v "no crontab")

# Copy all logs to the report

echo "Generating Report"
cp -r /var/log/ $Directory/logs/ 

# Create the HTML report
report="<html>
<head>
<title>Live Forensics Report for $hostname</title>
<style>
body {
font-family: Arial, sans-serif;
}
h1, h2, h3 {
color: #4B0082;
}
pre {
background-color: #F5F5F5;
padding: 10px;
border-radius: 5px;
}
#logo {
max-width: 200px;
height: auto;
}
.tab {
display: none;
}
.tab.active {
display: block;
}
.center {
  display: block;
  margin-left: auto;
  margin-right: auto;
  width: 50%;
}
</style>
<script>
function openTab(tabName) {
var i, tabcontent, tablinks;
tabcontent = document.getElementsByClassName('tab');
for (i = 0; i < tabcontent.length; i++) {
tabcontent[i].className = tabcontent[i].className.replace(' active', '');
}
document.getElementById(tabName).className += ' active';
}
</script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.0.0/dist/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
<script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/popper.js@1.12.9/dist/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.0.0/dist/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
<body>
<img id='logo' src='https://github.com/abr4xc/llft/raw/main/linux.png' class="center">
<h1 class="center">Live Forensics Report for $hostname</h1>
<div id='menu' class="btn-group" role="group">
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('logged-in-users')\">Users information</button>
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('command-history')\">Command history</button>
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('modified-files')\">Last modified and open files</button>
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('open-connections')\">Open network connections</button>
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('suspicious-processes')\">Suspicious processes</button>
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('audit-logs')\">Audit logs</button>
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('login-history')\">Login history</button>
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('running-processes')\">Running processes and connections</button>
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('schedule-task')\">Schedule Tasks</button>
</div>
<div id='presentation' class='tab active'><h1 class="center">Linux live Forensics tool</h1><h2 class="center">Investigator</h2><pre class="center">$auditor_name</pre><h2 class="center">Case ID</h2><pre class="center">$case_name</pre><h2 class="center">Case Location</h2><pre class="center">$case_location</pre></div>
<div id='logged-in-users' class='tab'><h2>Logged-in users:</h2><pre>$logged_in_users</pre><h2>User account changes:</h2><pre>$user_account_changes</pre><h2>Users in the system:</h2><pre>$all_users_system</pre></div>
<div id='command-history' class='tab'><h2>Command history:</h2>$command_history</div>
<div id='modified-files' class='tab'><h2>Last modified files from all users:</h2><pre>$modified_files</pre><h2>File access history:</h2><pre>$file_access_history</pre><h2>Open filess:</h2><pre>$open_files</pre></div>
<div id='open-connections' class='tab'><h2>Open network connections:</h2><pre>$open_connections</pre></div>
<div id='suspicious-processes' class='tab'><h2>Suspicious processes:</h2><pre>$suspicious_processes</pre></div>
<div id='audit-logs' class='tab'><h2>Audit logs:</h2><pre>$audit_logs</pre></div>
<div id='login-history' class='tab'><h2>Failed login attempts:</h2><pre>$failed_logins</pre><h2>Login history:</h2><pre>$login_history</pre></div>
<div id='running-processes' class='tab'><h2>Running processes:</h2><pre>$running_processes</pre><h2>processes ports and connections:</h2><pre>$net_pro</pre></div>
<div id='schedule-task' class='tab'><h2>Schedule Tasks:</h2><pre>$schredule_task</pre></div>
<p class="center">coded for incident responders by <a href="https://www.linkedin.com/in/abr4x/">Omar Avilez</a></p>
</body>
</html>"

# Write the report to the output file
echo -e "$report" > "$Directory/$output_file"
echo "Report saved to $Directory/$output_file"
