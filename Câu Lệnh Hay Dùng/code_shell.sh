#!/bin/bash
log_direc="/var/log/snort/alert"
email="wanoniw656@animex98.com" #Change mail here!!
snort_run="/home/weed/Desktop/snort.sh"
snort_pro="/usr/local/bin/snort"

#-------------------------------------------------------------------
Time=$(date +"%m/%d-%H:%M:%S");

if [ -f "$log_direc"  ]; then
echo "Alert's Log is existed!!!!!"
	if [ -s "$log_direc" ]; then
	echo $?
	echo "Alert's Log has data!!!!!"
		awk 'NR==1' $log_direc 
		tcp=$(grep -n "TCP SYN" $log_direc | cut -d : -f 1 | tail -1);
		echo "$tcp"
		udp=$(grep -n "UDP DOS" $log_direc | cut -d : -f 1 | tail -1);
		echo "$udp"
		icmp=$(grep -n "ICMP Flood" $log_direc | cut -d : -f 1 | tail -1);
		echo "$icmp"
		alert=""

		if [ "$tcp" != "" ]; then
			echo "TCP"
			
			tcp_title=$((tcp));
			tcp_time=$((tcp+2));
			tcp_ip=$((tcp+3));
		
			tcp_string1=$(awk -v a=$tcp_title 'NR==a' $log_direc)
			tcp_string2=$(awk -v b=$tcp_time 'NR==b' $log_direc)
			tcp_string3=$(awk -v c=$tcp_ip 'NR==c' $log_direc)
			tcp_string="${tcp_string1}'\n'${tcp_string2}'\n'${tcp_string3}'\n'";
			
		    #awk -v a=$tcp -v b=$from_tcp 'NR>=a&&NR<=b' $log_direc | mail -s "WARNING TCP DOS ATTACK1!!!" $email
		    #echo -e $tcp_string | mail -s "WARNING TCP DOS ATTACK1!!!" $email
		    alert="${alert}'\n'${tcp_string}'\n'"
		    echo -e "$alert"
		fi

		if [ "$udp" != "" ]; then
		echo "UDP"
		    #awk -v a=$udp -v b=$from_udp 'NR>=a&&NR<=b' $log_direc | mail -s "WARNING UDP DOS ATTACK2!!!" $email
		    
		    	udp_title=$((udp));
			udp_time=$((udp+2));
			udp_ip=$((udp+3));
			
		    	udp_string1=$(awk -v a=$udp_title 'NR==a' $log_direc)
			udp_string2=$(awk -v b=$udp_time 'NR==b' $log_direc)
			udp_string3=$(awk -v c=$udp_ip 'NR==c' $log_direc)
			udp_string="${udp_string1}'\n'${udp_string2}'\n'${udp_string3}'\n'";
		    alert="${alert}'\n'${udp_string}'\n'"
		    echo -e "$alert"
		fi
		 
		if [ "$icmp" != "" ]; then  
		echo "ICMP"
		    #awk -v a=$icmp -v b=$from_icmp 'NR>=a&&NR<=b' $log_direc | mail -s "WARNING ICMP PING ATTACK3!!!" $email
		    	icmp_title=$((icmp));
			icmp_time=$((icmp+2));
			icmp_ip=$((icmp+3));
			
		    	icmp_string1=$(awk -v a=$icmp_title 'NR==a' $log_direc)
			icmp_string2=$(awk -v b=$icmp_time 'NR==b' $log_direc)
			icmp_string3=$(awk -v c=$icmp_ip 'NR==c' $log_direc)
			icmp_string="${icmp_string1}'\n'${icmp_string2}'\n'${icmp_string3}'\n'";

		    alert="${alert}'\n'${icmp_string}'\n'"
		    echo -e "$alert"
		fi  
		
		#alert=`printf "$alert"`
		
		printf "$alert" | mail -s "WARNING DOS Attack!!!" "$email"
		cat "$log_direc" > /home/weed/Desktop/fileoutput.txt  
		> "$log_direc"
	else
		echo $? 
		echo "Alert's Log empty!!!!!"
	fi
#done
#if tail $log_direc | grep "$Time" && tail $log_direc | grep "TCP" ; then
 #   tail $log_direc | mail -s "WARNING TCP DOS ATTACK1!!!" $email
 #   cat "$log_direc" > /home/weed/Desktop/fileoutput.txt
 #   rm $log_direc

#elif tail $log_direc | grep "$Time" && tail $log_direc | grep "UDP" ; then
    #tail $log_direc | mail -s "WARNING UDP DOS ATTACK2!!!" $email
    #cat "$log_direc" > /home/weed/Desktop/fileoutput.txt
    #rm $log_direc
    
#elif tail $log_direc | grep "$Time" && tail $log_direc | grep "ICMP" ; then
 #   tail $log_direc | mail -s "WARNING ICMP PING ATTACK3!!!" $email
#    cat "$log_direc" > /home/weed/Desktop/fileoutput.txt
 #   rm $log_direc    

#else 
#echo "NOTHING HAPPENNED!!"
#fi

else
	echo "Alert's log is not OK!!!"
	echo "No file!!!" | mail -s "Call Snort!" $email
	killall $snort_pro
	sh $snort_run
fi	

