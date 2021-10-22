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
