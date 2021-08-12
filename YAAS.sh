#!/bin/bash


# -----------------------------
#|                             |
#| PLASE MODIFY THIS VARIABLES |
#|                             |
# -----------------------------

user_folder="" #We are going to create the CTF's file here, otherwise we are going to use your current directory.
gobuster_dic="" #We need this dictionary or another one to use with gobuster.
#hugo_dir="" #Put your Hugo path here.

##Colors
red='\e[0;31m' # Red
green='\e[0;32m' # Green
lgreen="\e[1;32m" # Light Green
orange='\e[0;33m' # Orange ?
blue='\e[0;34m' # Blue
purple='\e[0;35m' # Purple
cyan='\e[0;36m' # Cyan
white='\e[0;37m' # White
yellow="\e[1;33m" # Yellow
reset='\e[0m' # Text Reset

#Generals
version="1.1"

if [[ user_folder == "" ]]; then
	user_folder= $(pwd)
fi

function tool_checker(){
	banner
	box_out "Looking for necessary tools..."
	if [[ $(which nmap 2> /dev/null) ]]; then
		tool_nmap=true
	else
		tool_nmap=false
	fi
	if [[ $(which gobuster 2> /dev/null) ]]; then
		tool_gobuster=true
	else
		tool_gobuster=false
	fi
	if [[ $(which enum4linux 2> /dev/null) ]]; then
		tool_enum=true
	else
		tool_enum=false
	fi
	echo -e "[!] NMAP       : " $(check_result $tool_nmap)
	echo -e "[!] Gobuster   : " $(check_result $tool_gobuster)
	echo -e "[!] enum4linux : " $(check_result $tool_enum)
}

##Just some functions for output in boxes :)
function box_out(){
  local s=("$@") b w
  for l in "${s[@]}"; do
    ((w<${#l})) && { b="$l"; w="${#l}"; }
  done
  tput setaf 3
  echo " -${b//?/-}-
| ${b//?/ } |"
  for l in "${s[@]}"; do
    printf '| %s%*s%s |\n' "$(tput setaf $(shuf -i 1-10 -n 1))" "-$w" "$l" "$(tput setaf 3)"
  done
  echo "| ${b//?/ } |
 -${b//?/-}-"
  tput sgr 0
}

##Our ugly banner
function banner(){
	clear
	echo ""
	echo -e "${red}__  _____    ___   _____${reset}"
	echo -e "${red}\ \/ /   |  /   | / ___/${reset}"
	echo -e "${red} \  / /| | / /| | \__ \ ${cyan} Yet Another Automation Script${reset}"
	echo -e "${red} / / ___ |/ ___ |___/ / ${cyan} Version ${version}${reset}"
	echo -e "${red}/_/_/  |_/_/  |_/____/  ${cyan} -By Lanfran02${reset}"
	echo ""
}

##Check results and give them color
function check_result(){
	if [[ "$*" == false ]]; then
		result=${red}NO${reset}
	else
		result=${green}YES${reset}
	fi
	echo $result
}

##Help message
function print_help(){
  banner
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-b] [-f] -i Machine_IP -n Folder_Name [-h]

Beginners friendly automation script to run in the recon phase of a CTF. Designed to avoid repeating always the same commands...
Created by a lazy human, for lazy humans ;) 

Available options:

-b               Batch mode, run the scan with default config.
-f               Run the NMAP Scan faster.
-i               Set the Machine's IP address.
-n [Folder_Name] Name for the Folder.
-h               Print this help and exit.

Examples:
  $(basename "${BASH_SOURCE[0]}")
  $(basename "${BASH_SOURCE[0]}") -f 
  $(basename "${BASH_SOURCE[0]}") -i localhost -b
  $(basename "${BASH_SOURCE[0]}") -n mrrobot_THM -i 10.10.252.63 			
  $(basename "${BASH_SOURCE[0]}") -n potato_OFSC -i 10.10.152.12 -b -f 

EOF
}

##Flags
n_flag=''
i_flag=''
f_flag=false
h_flag=false
b_flag=false

while getopts 'n:i:fhb' flag; do
  case "${flag}" in
    n) n_flag="${OPTARG}" ;;
	i) i_flag="${OPTARG}" ;;
    f) f_flag='true' ;;
	b) b_flag='true' ;;
    h) h_flag= print_help 
		exit 1 ;;
  esac
done

##Starting with the output
banner

##Check if folder name is defined, otherwise, ask for it
if [[ $n_flag != "" ]]; then
	name_folder="$n_flag"
	echo "[+] Folder Name : " $name_folder	
else
	read -p "[+] Folder Name : " name_folder	
fi

##Get the IP of the machine
if [[ $i_flag != "" ]]; then
	ip="$i_flag"
	echo "[+] IP : " $ip
else
	read -p "[+] IP : " ip
fi

hugo_created=${red}NO${reset}

##Add an specific hostname for the given IP
if [[ $b_flag = false ]]; then
	read -p "[+] You want to add an specific hostname for the IP ? [y/N] : " add_host
	if [[ $add_host == "yes" || $add_host == "y" || $add_host == "YES" || $add_host == "Y" ]]; then
		read -p " ╰─ Please write it here : " name_host
		write_hosts=`echo "${ip} ${name_host}" | sudo tee -a /etc/hosts`
	fi
	#Ask for Hugo page
	read -p "[+] Create Page [y/N]: " hugo_page
	if [[ $name_folder != "" && $hugo_page == "yes" || $hugo_page == "y" || $hugo_page == "YES" || $hugo_page == "Y" ]]; then
		if [ -f "$hugo_dir" ]; then
			command cd "${hugo_dir}"
		else
			until [ -d "$hugo_input" ]; do
				box_out "PATH FOR HUGO NOT SET"
				read -p "[+] Hugo Path [$HOME] : " hugo_input
			done
			hugo_dir=$hugo_input
			command cd "${hugo_dir}"
		fi
		command hugo new "posts/$name_folder/index.md"
		hugo_created=${green}YES${reset}
	fi
fi
command cd "${user_folder}"

#Create the folder or use the created one
if [[ $name_folder != "" ]]; then
	if command mkdir "$name_folder" 2> /dev/null ; then
		command cd "${user_folder}${name_folder}"
	else
		command cd "${user_folder}${name_folder}"
	fi
fi
#Check if we have all the necessary tools
tool_checker

#Launching NMAP if we have the IP
if [[ $ip != "" ]]; then
	echo ""
	box_out "Checking if host is UP and accepting ping..."
	if [[ $(ping -c 2 $ip 2> /dev/null) ]]; then
		echo -e "${lgreen}Everything is UP and running${reset}"
		ip_tun0=`hostname -I | awk '{print $2}'`
		if [[ $ip_tun0 == "" ]]; then
			ip_tun0="N/A"
		fi
	else
		if [[ "$b_flag" = false ]]; then
			echo -e "${red}Host is not accepting ping (Windows?) or unknown hostname${reset}"
			read -p "[+] Continue? [Y/n] : " continue_ping
			if [[ $continue_ping == "no" || $continue_ping == "n" || $continue_ping == "NO" || $continue_ping == "N" ]]; then
				echo ""
				echo -e "${red}Exiting now...${reset}"
				exit 1;
			fi
		fi
	fi
	box_out "Launching NMAP Scan..."
	if [[ "$f_flag" = true ]]; then
		command sudo nmap $ip -p- -sS --min-rate 5000 -n -Pn -o nmap_Scan
		open_ports=`cat nmap_Scan | grep open | awk -F/ '{print $1}' ORS=',' | rev | cut -c 2- | rev`
	else
		first_nmap=`sudo nmap $ip -p- -sS --min-rate 5000 -n -Pn -o output_nmap`
		open_ports=`cat output_nmap | grep open | awk -F/ '{print $1}' ORS=',' | rev | cut -c 2- | rev`
		sudo nmap -sS -sV -sC $ip -p $open_ports -o nmap_Scan
	fi
fi

#Reading the output of the NMAP scan
web_server=false
samba=false
ftp=false
ftp_anon=false
ssh=false

for line in $(cat nmap_Scan | grep open)
do
	if [[ $line =~ (http|web|server) ]]; then
		web_server=true
	elif [[ $line =~ (Samba|netbios-ssn) ]]; then
		samba=true
	elif [[ $line =~ (ftp) ]]; then
		ftp=true
		if [[ $(cat nmap_Scan | grep "Anonymous FTP login allowed") ]] ; then
			ftp_anon=true
		fi
	elif [[ $line =~ (ssh) ]]; then
		ssh=true
	fi
done

if [[ $b_flag = false ]]; then
	#IF we have a web server, ask for the port and launch a common gobuster
	if [[ "$web_server" = true ]]; then

		box_out "WEB SERVER DETECTED"
		read -p "[+] Scan Web Server? [y/N] : " scan_web
		if [[ $scan_web == "yes" || $scan_web == "y" || $scan_web == "Y" || $scan_web == "YES" ]]; then
			read -p "[+] Port? [80] : " port_web
			if [[ $port_web == "" ]]; then
				port_web=80
			fi
			if [[ $gobuster_dic == "" ]]; then
				if [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
					gobuster_dic="/usr/share/wordlists/dirb/common.txt"
				else
					until [ -f "$gobuster_input" ]; do
						box_out "DICTIONARY FOR GOBUSTER NOT FOUND"
						read -p "[+] Dictionary Path [/usr/share/wordlists/dirb/common.txt] : " gobuster_input
					done
				fi
			else
				if [ -f "$gobuster_dic" ]; then
					gobuster_dic=$gobuster_dic
				else
					until [ -f "$gobuster_input" ]; do
						box_out "DICTIONARY FOR GOBUSTER NOT FOUND"
						read -p "[+] Dictionary Path [/usr/share/wordlists/dirb/common.txt] : " gobuster_input
					done
					gobuster_dic=$gobuster_input
				fi
			fi

			gobuster dir -w ${gobuster_dic} --threads 50 -x txt,old,bak,zip,php,html,txt,bak,old,pdf -u "http://$ip:$port_web" 2> /dev/null | tee Gobuster_Scan.txt
			cat Gobuster_Scan.txt | grep '301\|200' |  awk -F/ '{print $2}'| sed -e 's/\s.*$//' > endpoints.txt

			for endpoint in $(cat endpoints.txt)
			do 
				result_curl=`curl -s http://$ip:$port_web/$endpoint > searchingfor_WP.txt`
				if [[ $(cat searchingfor_WP.txt | grep Moved) ]]; then
					result_curl=`curl -s http://$ip:$port_web/$endpoint/ > searchingfor_WP.txt`
				fi
				if [[ $(cat searchingfor_WP.txt | grep wordpress) ]]; then
					endpoint_wp=${endpoint}
					box_out "We detected a potential WordPress page"
					echo "[!] Endpoint Name : " $endpoint_wp
					read -p "[+] Scan WordPress? [y/N] : " scan_wp
					if [[ $scan_wp == "yes" || $scan_wp == "y" || $scan_wp == "Y" || $scan_wp == "YES" ]]; then
						wpscan --no-update -o WP_SCAN.json -f json -e vp,vt,cb,u --url "http://$ip:$port/$endpoint_wp"
					fi
					break
				fi
			done
		fi
	fi
	#IF we have a Smamba server launch a enumeration for users and shares with enum4linux
	if [[ "$samba" = true ]]; then
		echo ""
		box_out "SAMBA SHARE DETECTED"
		read -p "[+] Scan Samba Server? [y/N] : " scan_samba
		if [[ $scan_samba == "yes" || $scan_samba == "y" || $scan_samba == "Y" || $scan_samba == "YES" ]]; then
			command enum4linux -U -S "$ip"
		fi
	fi

	if [[ "$ftp_anon" = true ]]; then
		echo ""
		box_out "Anonymous FTP login allowed 
		(For username use: Anonymous)"
		read -p "[+] Login now? [y/N] : " login_ftp
		if [[ $login_ftp == "yes" || $login_ftp == "y" || $login_ftp == "Y" || $login_ftp == "YES" ]]; then
			command ftp "$ip"
		fi
	fi
fi
#Echo all the results
banner
box_out "Final output: "
echo -e "[+] Tun0 IP             :  ${cyan}${ip_tun0}${reset}"
echo -e "[+] Machine IP          :  ${cyan}${ip}${reset}"
echo -e "[+] Open Port/s         :  ${lgreen}${open_ports}${reset}"
echo -e "[+] SSH Server/s found? : " $(check_result  $ssh)
echo -e "[+] FTP Server/s found? : " $(check_result  $ftp)
if [[ "$ftp" = true && "$f_flag" == false ]]; then
	echo -e " ╰─ Anonymous Login enabled? : " $(check_result  $ftp_anon)	
fi
echo -e "[+] Web Server/s found? : " $(check_result  $web_server)
if [[ $scan_web == "yes" || $scan_web == "y" || $scan_web == "Y" || $scan_web == "YES" ]]; then
	echo -e " ╰─ Endpoint/s detected :  ${lgreen}$(cat endpoints.txt | awk -F/ '{print $0}' ORS=', ' | cut -c 3-| rev | cut -c 3- | rev)${reset}"
	if [[ $scan_wp == "yes" || $scan_wp == "y" || $scan_wp == "Y" || $scan_wp == "YES" ]]; then
		echo -e " ╰─ User/s found        :  ${lgreen}$(cat WP_SCAN.json | jq '.users | keys' | awk -F/ '{print $0}' ORS='' | cut -c 4- | rev | cut -c 2- | rev)${reset}"
	fi
fi
echo -e "[+] Samba Server found? : " $(check_result $samba)
echo -e "[+] Hugo post created?  : " $hugo_created


rm -f endpoints.txt output_nmap searchingfor_WP.txt 2> /dev/null