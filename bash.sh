#!/bin/bash
echo "Escreva qual site vc deseja"
read site

nmap $site -vv -sS -sV --open -o nmap.txt
dirb $site -w /usr/share/dirb/wordlists/common.txt -o dirb.txt
curl $site -v -V -A -i -d --output curl.txt
nikto -h $site -port 3000 -Tuning comprehensive -output nikto.txt
nikto -h $site -p 3000 -C all -no404 -output nikto2.txt
wapiti -u $site -o wapiti-results.txt -f txt



