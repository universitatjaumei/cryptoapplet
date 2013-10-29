#!/bin/bash
# By Paul Santapau
#
# Description:  Get certificates from subdirectories at current directory, analizes them and gives a dokuwiki 
#               table with its data as output  
# 
# Depend:       Openssl  
# Note:         The script assumes that certificates have already been uploaded to the dokuwiki media manager and the are under 
#               the namespaces certs:original_subdirectory: 
#
# Version:      0.0.1 (30-04-2009)


#Build the wiki page
echo "^ Fichero ^ Subject ^ Issuer ^ Serial ^ Start Date ^ End Date ^" 
#

for i in $(find -maxdepth 1 -type d -not -regex "\.")
do
  cd $i
  for j in * 
  do 
    egrep ".*-----BEGIN.*CERTIFICATE-----.*" "$j" > /dev/null
    if [ $? -eq 0 ] 
    then 
	cod=PEM
    else
	cod=DER 
    fi
    sub_hash=$(openssl x509 -in "$j" -inform $cod -subject_hash -noout)
    iss_hash=$(openssl x509 -in "$j" -inform $cod -issuer_hash -noout)
    
    if [ $iss_hash = $sub_hash ]
    then
	iss="SELF SIGNED" 
    else
	iss=$(openssl x509 -in "$j" -inform $cod -issuer -noout | sed  "s/issuer=//" | sed "s/\/\([COL]\)/\\\\\\\\ \1/g")
    fi
    
    sub=$(openssl x509 -in "$j" -inform $cod -subject -noout | sed  "s/subject=//" | sed "s/\/\([COL]\)/\\\\\\\\ \1/g")
    ser=$(openssl x509 -in "$j" -inform $cod -serial -noout | sed "s/serial=//" |  sed "s/\//\\\\/") 
    sdat=$(openssl x509 -in "$j" -inform $cod -startdate -noout | sed "s/notBefore=//" | sed "s/\//\\\\/") 
    edat=$(openssl x509 -in "$j" -inform $cod -enddate -noout | sed  "s/notAfter=//" |  sed "s/\//\\\\/")
      
    #Build the wiki page: 
    dir=${i:2}
    echo "| {{certs:$dir:$j|}}  |$sub  |$iss  |  $ser  |  $sdat  |  $edat  |"
    #
    
  done 
  cd - >/dev/null 
done