#!/bin/bash

PATH=$PATH:/usr/bin:/bin:/sbin:/usr/sbin

ATTEMPTS=10;    # NUMBER OF ATTEMPTS IN A GIVEN INTERVAL
INTERVAL=600;   # INTERVAL (IN SECONDS) TO WATCH FOR FAILED ATTEMPTS - HISTORICALLY FROM CURRENT TIME
PERMBAN=100;    # AFTER THIS NUM OF FAILED ATTEMPTS, BAN UNTIL LOG ROTATES
BLOCKSECS=3600; # AFTER THIS TIME (IN SECONDS), UNBLOCK A BLOCKED IP
BLOCKED_ALREADY=""
BLOCKED_NOW=""
SKIPPED=""
EXPIRED_BLOCK=""
NOW=`date '+%s'`

# OpenWRT specific paths
IPLIST_LOG="/tmp/ip-list.log"
BANNED_LOG="/tmp/banned.log"
THISRUN_FILE="/tmp/this-run"
LASTRUN_FILE="/tmp/last-run"

isip() {
	ISIP=0
	local testip=$1
	if [ $(echo $testip | sed 's/[^.]//g' | awk '{print length; }' 2> /dev/null) -eq 3 ]; then
		# Additional validation for proper IP format
		if echo $testip | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
			ISIP=1
		fi
	fi
}

fail2ban() {
        # echo failing $IP with count $COUNT and lastcount $LASTCOUNT
        IP=$IP
        EXISTS=`iptables -n -L | grep $IP | wc -l`
        IS_LOCAL=`echo $IP | grep -E '^10\.|^192\.168|^127\.|^172\.(1[6-9]|2[0-9]|3[01])\.' | wc -l`
        if [ $EXISTS -gt 0 ]; then
		BLOCKED_ALREADY+=",$IP:$COUNT"
                # echo "IP $IP is already blocked"
        elif [ $IS_LOCAL -eq 1 ]; then
		SKIPPED+=",$IP:$COUNT"
                # echo "IP is local IP.  Not blocking"
        else
		if [ ! "$IP" == "" ]; then
	                # echo "Blocking IP $IP after $COUNT abuses."
	                BLOCKED_NOW+=",$IP:$COUNT"
	                iptables -I INPUT 1 -j DROP -s $IP
	                echo "`date`:$IP:$NEWCOUNT:$COUNT:BLOCKED" >> $BANNED_LOG
		fi
        fi
}

updateList() {
        NOW=`date '+%s'`
        sed -i "s/:$IP:$LASTCOUNT:.*$/:$IP:$COUNT:$NOW/" $IPLIST_LOG
}

updateTime() {
	NOW=`date '+%s'`
	sed -i "s/:$IP:$LASTCOUNT:.*$/:$IP:$LASTCOUNT:$NOW/" $IPLIST_LOG
}

showList() {
	LIST="$2"
	DESCRIPTION="$1"
	if [ ! "$LIST" == "" ]; then  
        	echo "$DESCRIPTION"
        	for i in `echo "$LIST" | tr ',' '\n'`                                                                       
        	do                                                                                                   
        	        BIP=$(echo $i | sed -e 's/:.*$//')                                                           
        	        BCOUNT=$(echo $i | sed -e 's/^.*://')                                                        
			if [ ! "$BIP" == "" ] && [ ! "$BIP" == "$LIST" ]; then
		                echo "  $BIP ($BCOUNT attempts)"                                                                            
			fi
        	done
	fi	
}

checkExpired() {
	BLOCKED=$(iptables -L INPUT -n | grep "^DROP" | awk '{print $4}' | grep -v '0.0.0.0/0')
	for blocked_ip in $BLOCKED; do
		# Find this IP in our tracking log
		for i in `grep ":$blocked_ip:" $IPLIST_LOG 2>/dev/null`; do
		        IP=`echo $i | cut -d':' -f2`                                                                                                                                 
		        isip $IP                                                                                                                                                     
		        COUNT=`echo $i | cut -d':' -f3`                                                                                                                              
		        LASTACTION=`echo $i | cut -d':' -f4`                                                                                                                         
		        if [ $((NOW-LASTACTION)) -gt $BLOCKSECS ] && [ ! "$IP" == "" ] && [ $ISIP -eq 1 ] && [ $COUNT -lt $PERMBAN ]; then                                           
		                LINE=`iptables -L INPUT -n --line-numbers | grep "$IP" | head -1 | cut -d' ' -f1`                                                                           
		                if [ ! "$LINE" == "" ]; then                                                                                                                         
		                        echo "Removing block on $IP (blocked for $((NOW-LASTACTION)) seconds)"                                                                                                                 
					echo "$(date):$IP:UNBLOCKED" >> $BANNED_LOG
		                        EXPIRED_BLOCK+=",$IP"                                                                                                                      
		                        iptables -D INPUT $LINE                                                                                                                      
		                fi                                                                                                                                                   
		        fi
		done                                                                                                                                                           
	done                                   
}

# Create necessary files if they don't exist
if [ ! -f $IPLIST_LOG ]; then
        touch $IPLIST_LOG
fi

if [ ! -f $BANNED_LOG ]; then
        touch $BANNED_LOG
fi

# CLEANUP - KEEP ONLY HACKERS FROM TODAY
echo -n "" > ${IPLIST_LOG}.new
IFS="
"
for i in `grep "^$(date +%Y%m%d):" $IPLIST_LOG 2>/dev/null`
do
	if [ ! "$i" == "" ]; then
		echo $i >> ${IPLIST_LOG}.new
	fi
done
mv ${IPLIST_LOG}.new $IPLIST_LOG

# Check if we should run (basic change detection)
if [ -f $THISRUN_FILE ]; then
	mv $THISRUN_FILE $LASTRUN_FILE
else
	touch $LASTRUN_FILE
fi

# Get current log size for change detection
logread | wc -l > $THISRUN_FILE
CHANGE=$(diff $LASTRUN_FILE $THISRUN_FILE 2>/dev/null | wc -l)
if [ $CHANGE -eq 0 ]; then
	echo "No change since last run"
	checkExpired
	exit
fi

# Parse dropbear logs for failed password attempts
# Look for "Bad password attempt" lines and extract IPs
IPLIST=`logread | grep "Bad password attempt" | grep -oE 'from [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed 's/from //' | sort | uniq -c | sed -e 's/^ *//' | sed -e 's/ /:/' | sed -e "s/^\(.*\)$/$(date +%Y%m%d):\1/"`

for i in `echo "$IPLIST"`
do
	#echo "Processing: $i"
        COUNT=`echo $i | cut -d':' -f2`
        IP=`echo $i | cut -d':' -f3`
	DATE=`echo $i | cut -d':' -f1`
	isip $IP
	
	if [ $ISIP -eq 0 ]; then
		continue
	fi
	
        LASTCOUNT=`grep ":$IP:" $IPLIST_LOG 2>/dev/null | cut -d':' -f3`
        ELAPSED=`grep ":$IP:" $IPLIST_LOG 2>/dev/null | cut -d':' -f4 | sed -e 's/\n//g'`
	
	if [ ! "$ELAPSED" == "" ]; then
		ELAPSED=$((NOW-ELAPSED))
	else
		ELAPSED=0
	fi
	
        if [ "$COUNT" == "" ]; then
                COUNT=0
        fi
        if [ "$LASTCOUNT" == "" ]; then
                LASTCOUNT=0
        fi
        NEWCOUNT=$((COUNT-LASTCOUNT))
        
        # Add new IPs to tracking
        if [ "$LASTCOUNT" == "" ] || [ $LASTCOUNT -eq 0 ]; then
                echo "$DATE:$IP:$COUNT:$NOW" >> $IPLIST_LOG
                echo "Adding $IP to tracking log with $COUNT attempts"
        fi
	
	echo "IP:$IP NEWCOUNT:$NEWCOUNT LASTCOUNT:$LASTCOUNT COUNT:$COUNT ELAPSED:$ELAPSED ISIP:$ISIP"
	
        # Decide whether to ban
        if [ $NEWCOUNT -ge $ATTEMPTS ] && [ $ISIP -eq 1 ] && ( [ $ELAPSED -le $INTERVAL ] || [ $COUNT -gt $PERMBAN ] ); then
                if [ $LASTCOUNT -ne 0 ]; then
			echo "Updating IP:$IP with NEWCOUNT:$NEWCOUNT (threshold: $ATTEMPTS attempts in $INTERVAL seconds)"
                        updateList
                fi
                fail2ban
	elif [ $NEWCOUNT -ge $ATTEMPTS ] && [ $ISIP -eq 1 ]; then
		echo "Updating timestamp for IP $IP; +$NEWCOUNT attempts since last update (outside time window)"
		updateTime
        fi
done

checkExpired

IFS=","

echo "=== Fail2Ban Status ==="
showList "Already Blocked" "$BLOCKED_ALREADY"
showList "Newly Blocked" "$BLOCKED_NOW"
showList "Skipped (Local IPs)" "$SKIPPED"
showList "Unblocked (Expired)" "$EXPIRED_BLOCK"

if [ "$BLOCKED_NOW" != "" ] || [ "$EXPIRED_BLOCK" != "" ]; then
	echo ""
	echo "Current iptables DROP rules:"
	iptables -L INPUT -n --line-numbers | grep DROP | grep -v "0.0.0.0/0"
fi