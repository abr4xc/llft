#!/bin/bash

cat << "EOF"                     
  _      _                    _      _____           ______ ____                     _            _______          _ 
 | |    (_)                  | |    |_   _|         |  ____/ __ \                   (_)          |__   __|        | |
 | |     _ _ __  _   ___  __ | |      | |_   _____  | |__ | |  | |_ __ ___ _ __  ___ _  ___ ___     | | ___   ___ | |
 | |    | | '_ \| | | \ \/ / | |      | \ \ / / _ \ |  __|| |  | | '__/ _ \ '_ \/ __| |/ __/ __|    | |/ _ \ / _ \| |
 | |____| | | | | |_| |>  <  | |____ _| |\ V /  __/ | |   | |__| | | |  __/ | | \__ \ | (__\__ \    | | (_) | (_) | |
 |______|_|_| |_|\__,_/_/\_\ |______|_____\_/ \___| |_|    \____/|_|  \___|_| |_|___/_|\___|___/    |_|\___/ \___/|_
EOF

if [[ $EUID -ne 0 ]]; then
  echo "[!] This script must be run as root."
  exit 1
fi

date=$(date +"%Y-%m-%d_%H-%M-%S")

read -p "Enter the Investigator name: " auditor_name
read -p "Enter the case ID: " case_name
read -p "Enter the case Location: " case_location

hostname=$(hostname)
uptime_info=$(uptime -p)
os_info=$(cat /etc/os-release)
kernel_info=$(uname -a)

Directory="$hostname-$date"
mkdir -p "$Directory/logs"
output_file="$hostname-$date.html"

logged_in_users=$(who)
all_users_system=$(getent passwd)
lastlog_entries=$(lastlog | grep -v 'Never')
user_account_changes=$(grep "useradd\|usermod\|userdel" /var/log/auth.log)
login_history=$(last | head -n 20)
user_switches=$(grep -Ei "sudo|su|session opened|session closed" /var/log/auth.log | tail -n 100)
failed_logins=$(grep 'authentication failure' /var/log/auth.log | tail -n 10)

modified_files=$(find /home -type f \
  ! -path "/home/*/.cache/*" \
  ! -path "/home/*/.local/share/Trash/*" \
  ! -path "$PWD/*" \
  -printf '%TY-%Tm-%Td %TH:%TM:%.2TS %u %p\n' | sort -r | head -n 100)

command_history=""
for user in $(who | awk '{print $1}' | sort -u); do
  history_file="/home/$user/.bash_history"
  if [ -f "$history_file" ]; then
    user_history=$(tail -n 50 "$history_file")
    command_history+="\n<h3>Command history for $user:</h3>\n<pre>$user_history</pre>"
  fi
done

open_files=$(lsof -nP -V | head -n 500)
file_access_history=$(ausearch -ua $(id -u) -i -ts today | grep "type=SYSCALL.*exe=" | awk '{print $1" "$2" "$13" "$14}')
audit_logs=$(ausearch -ua $(id -u) -i -ts today)
open_connections=$(ss -tunlp)
net_pro=$(echo -e "
$(netstat -anop 2>/dev/null)")
running_processes=$(ps aux)
suspicious_processes=$(ps -eo pid,user,%cpu,cmd --sort=-%cpu | grep -Ei 'nc|bash|sh|nmap|wget|curl|perl|python|ruby|php' | head -n 20)
schredule_task=$(for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null | grep -v '^#' | grep -v '^$' && echo "----"; done)

cp -r /var/log/ "$Directory/logs/"

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
white-space: pre-wrap;
word-wrap: break-word;
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
var i, tabcontent;
tabcontent = document.getElementsByClassName('tab');
for (i = 0; i < tabcontent.length; i++) {
tabcontent[i].className = tabcontent[i].className.replace(' active', '');
}
document.getElementById(tabName).className += ' active';
}
</script>
<link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap@4.0.0/dist/css/bootstrap.min.css\">
<script src=\"https://code.jquery.com/jquery-3.2.1.slim.min.js\"></script>
<script src=\"https://cdn.jsdelivr.net/npm/popper.js@1.12.9/dist/umd/popper.min.js\"></script>
<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@4.0.0/dist/js/bootstrap.min.js\"></script>
</head>
<body>
<img id='logo' src='https://github.com/abr4xc/llft/raw/main/linux.png' class="center">
<h1 class="center">Live Forensics Report for $hostname</h1>
<div id='menu' class="btn-group" role="group">
<button type=\"button\" class=\"btn btn-secondary\" onclick=\"openTab('presentation')\">Overview</button>
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
<div id='presentation' class='tab active'>
<h1 class="center">Linux Live Forensics Tool</h1>
<h2 class="center">Investigator</h2><pre class="center">$auditor_name</pre>
<h2 class="center">Case ID</h2><pre class="center">$case_name</pre>
<h2 class="center">Case Location</h2><pre class="center">$case_location</pre>
<h2 class="center">Hostname</h2><pre class="center">$hostname</pre>
<h2 class="center">Extraction Time</h2><pre class="center">$date</pre>
<h2 class="center">System Uptime</h2><pre class="center">$uptime_info</pre>
<h2 class="center">System Info</h2><pre class="center">$kernel_info

$os_info</pre>
</div>
<div id='logged-in-users' class='tab'><h2>Logged-in users:</h2><pre>$logged_in_users</pre><h2>User account changes:</h2><pre>$user_account_changes</pre><h2>Users in the system:</h2><pre>$all_users_system</pre></div>
<div id='command-history' class='tab'><h2>Command history:</h2>$command_history</div>
<div id='modified-files' class='tab'><h2>Last modified files from all users:</h2><pre>$modified_files</pre><h2>File access history:</h2><pre>$file_access_history</pre><h2>Open files:</h2><pre>$open_files</pre></div>
<div id='open-connections' class='tab'><h2>Open network connections:</h2><pre>$open_connections</pre></div>
<div id='suspicious-processes' class='tab'><h2>Suspicious processes:</h2><pre>$suspicious_processes</pre></div>
<div id='audit-logs' class='tab'><h2>Audit logs:</h2><pre>$audit_logs</pre></div>
<div id='login-history' class='tab'><h2>Failed login attempts:</h2><pre>$failed_logins</pre><h2>Login history:</h2><pre>$login_history</pre><h2>User switch / privilege escalation events:</h2><pre>$user_switches</pre></div>
<div id='running-processes' class='tab'><h2>Running processes:</h2><pre>$running_processes</pre><h2>Processes ports and connections:</h2><pre>$net_pro</pre></div>
<div id='schedule-task' class='tab'><h2>Schedule Tasks:</h2><pre>$schredule_task</pre></div>
<p class="center">coded for incident responders by <a href="https://www.linkedin.com/in/abr4x/">Omar Avilez</a></p>
</body>
</html>"

echo -e "$report" > "$Directory/$output_file"
echo "Report saved to $Directory/$output_file"
