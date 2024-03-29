#!/usr/bin/env bash
#Version: 1.0

# The script needs to be executed as ./waf_attck_scripts.sh URLS.txt
# URLS.txt needs to contain a list of full URLs separated on new lines
urls=$1

IFS=$'\n' read -d '' -r -a list < $urls

echo "Number of sites loaded for attacks: " ${#list[@]}
#echo ${list[@]}

# This will check if the report file already exists. If not, it will create one with the proper headings
file=./report.txt
if [ -e "$file" ]; then
    echo ""
else 
    echo -e "Timestamp \t URL \t Attack \t Imperva \t SigSci \t Undetected" >> $file
    echo ""
fi

# For every URL listed in the URLS.txt, each of the attacks below will be executed
for line in ${list[@]}; do

# Remove HTTP[S] from URL to be used in Host Headers
linehost=$(echo $line | sed -e 's/^http:\/\///g' -e 's/^https:\/\///g')

# Obtain IP of URL Host to be used in Host Headers
lineip=$(dig +short $linehost)

# Control
# This is just a simple CURL script to test that the URL is accessible
	echo "=========="
	echo "Control"
	echo "Launching Control against " $line

	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36" $line --stderr - | grep "403 Forbidden" &> /dev/null; then

		echo "Control completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t Control \t \t x \t " >> $file
        
    elif curl -v -s -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36" $line --stderr - | grep "Your request has been blocked" &> /dev/null; then

		echo "Control completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t Control \t x \t \t " >> $file
	else
		echo "Control completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t Control \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""
	
	
# XSS 1
	echo "=========="
	echo "Cross-site Scripting 1"
	echo "Launching XSS against " $line"/pharmacies"

	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36" $line"/pharmacies?chemical_name=Hydrocortisone+Sodium+Succinate+PF+For&days_of_supply=30&dosage_package_label=<whscheck><svg/onload=prompt()>&drug_name=A-Hydrocort&isSpecialty=false&ismaintenance=false&label=100+Mg+Injection&ndc=00409485605&package_or_frequency=1.0&page=5&q=A-Hydrocort&quantity=10" --stderr - | grep "403 Forbidden" &> /dev/null; then

		echo "XSS 1 completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t XSS 1 \t \t x \t " >> $file
        
    elif curl -v -s -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36" $line"/pharmacies?chemical_name=Hydrocortisone+Sodium+Succinate+PF+For&days_of_supply=30&dosage_package_label=<whscheck><svg/onload=prompt()>&drug_name=A-Hydrocort&isSpecialty=false&ismaintenance=false&label=100+Mg+Injection&ndc=00409485605&package_or_frequency=1.0&page=5&q=A-Hydrocort&quantity=10" --stderr - | grep "Your request has been blocked" &> /dev/null; then
    
    	echo "XSS 1 completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t XSS 1 \t x \t \t " >> $file
	else
		echo "XSS 1 completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t XSS 1 \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""

# SQLi 1
	echo "=========="
	echo "SQLi 1"
	echo "Launching SQLi 1 against " $line"/session"

	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -X POST $line"/engine/preview.php" -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36" -H 'Pragma: no-cache' -H "Origin: $line" -H 'Accept-Language: en-US,en;q=0.8' -H 'Upgrade-Insecure-Requests: 1' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Cache-Control: no-cache' -H 'Referer: $line/login' -H 'Connection: keep-alive' --data "object=1;print(3900*3790);exit" --compressed --stderr - | grep "403 Forbidden" &> /dev/null; then
    
    	echo "SQLi 1 completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t SQLi 1 \t \t x \t " >> $file
        
    elif curl -v -s -X POST $line"/engine/preview.php" -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36" -H 'Pragma: no-cache' -H "Origin: $line" -H 'Accept-Language: en-US,en;q=0.8' -H 'Upgrade-Insecure-Requests: 1' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Cache-Control: no-cache' -H 'Referer: $line/login' -H 'Connection: keep-alive' --data "object=1;print(3900*3790);exit" --compressed --stderr - | grep "Your request has been blocked" &> /dev/null; then

    	echo "SQLi 1 completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t SQLi 1 \t x \t \t " >> $file
	else
		echo "SQLi 1 completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t SQLi 1 \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""
	
# NMAP Scanner
	echo "=========="
	echo "NMAP Scanner"
	echo "Launching NMAP Scanner against " $line"/nmap"
	
	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -A "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" $line"/nmap/folder/check1516910621" --stderr - | grep "403 Forbidden" &> /dev/null; then

		echo "NMAP Scanner completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t NMAP Scanner \t \t x \t " >> $file
        
    elif curl -v -s -A "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" $line"/nmap/folder/check1516910621" --stderr - | grep "Your request has been blocked" &> /dev/null; then
    
    	echo "NMAP Scanner completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t NMAP Scanner \t x \t \t " >> $file
	else
		echo "NMAP Scanner completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t NMAP Scanner \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""

# CVE-2014-6271: Bash Remote Command Execution
	echo "=========="
	echo "Bash Remote Command Execution"
	echo "Launching Remote Command Execution against " $line"/cgi-bin"
	
	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -A '() { :;};echo; /bin/bash -c " echo 2014 | md5sum"' $line"/cgi-bin/test-cgi" --stderr - | grep "403 Forbidden" &> /dev/null; then

		echo "Bash Remote Command Execution completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t Bash Remote Command Execution \t \t x \t " >> $file
        
    elif curl -v -s -A '() { :;};echo; /bin/bash -c " echo 2014 | md5sum"' $line"/cgi-bin/test-cgi" --stderr - | grep "Your request has been blocked" &> /dev/null; then
    
    	echo "Bash Remote Command Execution completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t Bash Remote Command Execution \t x \t \t " >> $file
	else
		echo "Bash Remote Command Execution completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t Bash Remote Command Execution \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""

# Suspicious File Extension Access
	echo "=========="
	echo "Suspicious File Extension Access 1"
	echo "Launching Suspicious File Access 1 against " $line"/"
	
	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36" $line'/nice%%20ports,/trinity.txt.bak' --stderr - | grep "403 Forbidden" &> /dev/null; then

		echo "Suspicious File Extension Access 1 completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t Suspicious File Extension Access 1 \t \t x \t " >> $file
        
    elif curl -v -s -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36" $line'/nice%%20ports,/trinity.txt.bak' --stderr - | grep "Your request has been blocked" &> /dev/null; then
    
    	echo "Suspicious File Extension Access 1 completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t Suspicious File Extension Access 1 \t x \t \t " >> $file
	else
		echo "Suspicious File Extension Access 1 completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t Suspicious File Extension Access 1 \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""
# Masscan Scanner
	echo "=========="
	echo "Masscan Scanner"
	echo "Launching Masscan Scanner against " $line"/"
	
	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -A "masscan/1.0 (https://github.com/robertdavidgraham/masscan)" $line"/" --stderr - | grep "403 Forbidden" &> /dev/null; then

		echo "Masscan Scanner completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t Masscan Scanner \t \t x \t " >> $file
        
    elif curl -v -s -A "masscan/1.0 (https://github.com/robertdavidgraham/masscan)" $line"/" --stderr - | grep "Your request has been blocked" &> /dev/null; then
    
    	echo "Masscan Scanner completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t Masscan Scanner \t x \t \t " >> $file
	else
		echo "Masscan Scanner completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t Masscan Scanner \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""
# OpenVAS Scanner
	echo "=========="
	echo "OpenVAS Scanner"
	echo "Launching OpenVAS Scanner against " $line"/session"
	
	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -A 'Mozilla/5.0 [en] (X11, U; OpenVAS 8.0.9)' $line"/" --stderr - | grep "403 Forbidden" &> /dev/null; then

		echo "OpenVAS Scanner completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t OpenVAS Scanner \t \t x \t " >> $file
        
    elif curl -v -s -A 'Mozilla/5.0 [en] (X11, U; OpenVAS 8.0.9)' $line"/" --stderr - | grep "Your request has been blocked" &> /dev/null; then
    
    	echo "OpenVAS Scanner completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t OpenVAS Scanner \t x \t \t " >> $file
	else
		echo "OpenVAS Scanner completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t OpenVAS Scanner \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""
# Skipfish Scanner
	echo "=========="
	echo "Skipfish Scanner"
	echo "Launching Skipfish Scanner against " $line"/"
	
	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -A "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; SF/2.10b)" $line"/sfi9876.xslt" --stderr - | grep "403 Forbidden" &> /dev/null; then

		echo "Skipfish Scanner completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t Skipfish Scanner \t \t x \t " >> $file
        
    elif curl -v -s -A "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; SF/2.10b)" $line"/sfi9876.xslt" --stderr - | grep "Your request has been blocked" &> /dev/null; then
    
    	echo "Skipfish Scanner completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t Skipfish Scanner \t x \t \t " >> $file
	else
		echo "Skipfish Scanner completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t Skipfish Scanner \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""
# Paros Scanner
	echo "=========="
	echo "Paros Scanner"
	echo "Launching Paros Scanner against " $line"/"
	
	# Reset the timestamp to the current time and use PST
	timestamp=$(TZ=":America/Los_Angeles" date)

	if curl -v -s -A "Mozilla/5.0 (Windows NT 5.1; rv:22.0) Gecko/20100101 Firefox/22.0 Paros/3.2.13" -H "Host: $linehost" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' $line"/rightnowwp/wp-content/themes/rightnow/includes/uploadify/upload_settings_image.php" --stderr - | grep "403 Forbidden" &> /dev/null; then

		echo "Paros Scanner completed"
        echo "Attack Status: Blocked by Akamai"
        echo -e "$timestamp \t $line \t Paros Scanner \t \t x \t " >> $file
        
    elif curl -v -s -A "Mozilla/5.0 (Windows NT 5.1; rv:22.0) Gecko/20100101 Firefox/22.0 Paros/3.2.13" -H "Host: $linehost" -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' $line"/rightnowwp/wp-content/themes/rightnow/includes/uploadify/upload_settings_image.php" --stderr - | grep "Your request has been blocked" &> /dev/null; then
    
    	echo "Paros Scanner completed"
        echo "Attack Status: Blocked by Imperva"
        echo -e "$timestamp \t $line \t Paros Scanner \t x \t \t " >> $file
	else
		echo "Paros Scanner completed"
		echo "Attack Status: Undetected"
		echo -e "$timestamp \t $line \t Paros Scanner \t \t \t x" >> $file
	fi
	echo "=========="
	echo ""
