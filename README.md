# Hashcat Cheatsheet
```m
# MAX POWER
# force the CUDA GPU interface, optimize for <32 char passwords and set the workload to insane (-w 4).
# It is supposed to make the computer unusable during the cracking process
# Finnally, use both the GPU and CPU to handle the cracking
--force -O -w 4 --opencl-device-types 1,2
```
## Wrapcat - Automating hashcat commands
```
https://twitter.com/Haax9_/status/1340354639464722434?s=20
https://github.com/Haax9/Wrapcat

$ python wrapcat.py -m 1000 -f HASH_FILE.txt -p POT_FILE.txt --full --save
```
## Attack modes
```
-a 0 # Straight : hash dict
-a 1 # Combination : hash dict dict
-a 3 # Bruteforce : hash mask
-a 6 # Hybrid wordlist + mask : hash dict mask
-a 7 # Hybrid mask + wordlist : hash mask dict
```
## Charsets
```
?l # Lowercase a-z
?u # Uppercase A-Z
?d # Decimals
?h # Hex using lowercase chars
?H # Hex using uppercase chars
?s # Special chars
?a # All (l,u,d,s)
?b # Binary
```
## options
```
-m # Hash type
-a # Attack mode
-r # Rules file
-V # Version
--status # Keep screen updated
-b # Benchmark
--runtime # Abort after X seconds
--session [text] # Set session name
--restore # Restore/Resume session
-o filename # Output to filename
--username # Ignore username field in a hash
--potfile-disable # Ignore potfile and do not write
--potfile-path # Set a potfile path
-d # Specify an OpenCL Device
-D # Specify an OpenCL Device Type
-l # List OpenCL Devices & Types
-O # Optimized Kernel, Passwords <32 chars
-i # Increment (bruteforce)
--increment-min # Start increment at X chars
--increment-max # Stop increment at X chars
```
## Examples
```bash
# Benchmark MD4 hashes
hashcat -b -m 900

# Create a hashcat session to hash Kerberos 5 tickets using wordlist
hashcat -m 13100 -a 0 --session crackin1 hashes.txt wordlist.txt -o output.pot

# Crack MD5 hashes using all char in 7 char passwords
hashcat -m 0 -a 3 -i hashes.txt ?a?a?a?a?a?a?a -o output.pot

# Crack SHA1 by using wordlist with 2 char at the end 
hashcat -m 100 -a 6 hashes.txt wordlist.txt ?a?a -o output.pot

# Crack WinZip hash using mask (Summer2018!)
hashcat -m 13600 -a 3 hashes.txt ?u?l?l?l?l?l?l?d?d?d?d! -o output.pot

# Crack MD5 hashes using dictionnary and rules
hashcat -a 0 -m 0 example0.hash example.dict -r rules/best64.rules

# Crack MD5 using combinator function with 2 dictionnaries
hashcat -a 1 -m 0 example0.hash example.dict example.dict

# Cracking NTLM hashes
hashcat64 -m 1000 -a 0 -w 4 --force --opencl-device-types 1,2 -O d:\hashsample.hash "d:\WORDLISTS\realuniq.lst" -r OneRuleToRuleThemAll.rule

# Cracking hashes from kerberoasting
hashcat64 -m 13100 -a 0 -w 4 --force --opencl-device-types 1,2 -O d:\krb5tgs.hash d:\WORDLISTS\realhuman_phill.txt -r OneRuleToRuleThemAll.rule
```
```
# You can use hashcat to perform combined attacks
# For example by using wordlist + mask + rules
hashcat -a 6 -m 0 prenoms.txt ?d?d?d?d -r rules/yourule.rule

# Single rule used to uppercase first letter --> Marie2018
hashcat -a 6 -m 0 prenoms.txt ?d?d?d?d -j 'c'
```
## Scenario - Cracking large files (eg NTDS.dit) 
```
# Start by making a specific potfile and cracked files (clean environment)
# - domain_ntds.dit
# - domain_ntds_potfile.pot

# Goal is to run many different instances with different settings, so each one have
# to be quite quick

# You can generate wordlist using CeWL
# It usually works pretty well
cewl -d 5 -m 4 -w OUTFILE -v URL
cewl -d 5 -m 4 -w OUTFILE -o -v URL

# With some basic dictionnary cracking (use known wordlists)
# rockyou, hibp, crackstation, richelieu, kaonashi, french and english 
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 0 rockyou.txt --force -O

# Then start to use wordlists + masks + simple rule
# For special chars, you can use a custom charset : "?!%$&#-_@+=* "
# Multiple tests, multiples masks and multiples wordlists (including generated ones)
.\hashcat64.exe -m 1000 hashs.txt -a 6 .\french\* '?d?d?d?d' -j c --increment --force -O
.\hashcat64.exe -m 1000 hashs.txt -a 6 .\french\* -1 .\charsets\custom.chr '?1' -j c --force -O
.\hashcat64.exe -m 1000 hashs.txt -a 6 .\french\* -1 .\charsets\custom.chr '?d?1' -j c --force -O
.\hashcat64.exe -m 1000 hashs.txt -a 6 .\french\* -1 .\charsets\custom.chr '?d?d?1' -j c --force -O
.\hashcat64.exe -m 1000 hashs.txt -a 6 .\french\* -1 .\charsets\custom.chr '?d?d?d?1' -j c --force -O
.\hashcat64.exe -m 1000 hashs.txt -a 6 .\french\* -1 .\charsets\custom.chr '?d?d?d?d?1' -j c --force -O
.\hashcat64.exe -m 1000 hashs.txt -a 6 CEWL_WORDLIST.txt -1 .\charsets\custom.chr '?d?d?d?d?1' -j c --force -O
.\hashcat64.exe ...

# Same commands and behavior but using mask after the tested word (mode 7)
.\hashcat64.exe -m 1000 hashs.txt -a 7 '?d?d?d?d' .\french\* -j c --increment --force -O

# Then, wordlists + complex rules
# Once again run against multiple wordlists (including generated ones)
# Kaonashi and OneRuleToRuleThemAll can produce maaaaaassive cracking time
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 0 french.txt -r .rules\best64.rule --force -O
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 0 french.txt -r .rules\OneRuleToRuleThemAll.rule --force -O
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 0 french.txt -r .rules\best64.rule --force -O
.\hashcat64.exe ...

# Then smart bruteforce using masks (custom charset can be usefull too)
# Can be quite long, depending on the mask. Many little tests with different masks
# Knowing for example that password is min 8 char long, only 8+ masks
# Play by incrementing or decrementing char vs decimal (you can also use specific charset to reduce time)
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 3 '?u?l?l?l?d?d?d?d' --force -O
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 3 '?u?l?l?l?l?d?d?d' --force -O
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 3 '?u?l?l?l?l?l?d?d' --force -O
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 3 -1 .\charset\custom '?u?l?l?l?l?l?d?1' --force -O
.\hashcat64.exe ...

# Then increment mask size and play again
# Can be longer for 9 char and above.. Up to you to decide which masks and how long you wanna wait
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 3 '?u?l?l?l?d?d?d?d?d' --force -O
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 3 '?u?l?l?l?l?d?d?d?d' --force -O
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 3 '?u?l?l?l?l?l?d?d?d' --force -O
.\hashcat64.exe ...

# If you have few hashes and small/medium wordlist, you can use random rules
# And make several loops
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 0 wl.txt -g 1000000  --force -O -w 3

# You can use combination attacks
# For example, combine different names, or combine names with dates.. Then apply masks
# Directly using hashcat
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 1 wordlist1.txt wordlist2.txt --force -O
# Or in memory feeding, it allows you to use rules but not masks
.\combinator.exe wordlist1.txt wordlist2.txt | .\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 0 -rules .\rules\best64.rule --force -O
# Or create the wordlist before and use it
.\combinator.exe wordlist1.txt wordlist2.txt
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot -a 6 combinedwordlist.txt '?d?d?d?d' -j c --increment --force -O

# Finally use your already cracked passwords to build a new wordlist
.\hashcat64.exe -m 1000 hashs.txt --potfile-path potfile.pot --show | %{$_.split(':')[1]} > cracked.txt
.\hashcat64.exe -m 1000 hashs.txt -a 6 cracked.txt '?d?d?d?d' -j c --increment --force -O
.\hashcat64.exe -m 1000 hashs.txt -a 0 cracked.txt -r .rules\OneRuleToRuleThemAll.rule --force -O

# You can also checks the target in popular leaks to find some password
# Then try reuse or rules on them
```

# John Cheatsheet

## Cracking Modes
```m
# Dictionnary attack
./john --wordlist=password.lst hashFile

 # Dictionnary attack using default or specific rules
./john --wordlist=password.lst --rules=rulename hashFile
./john --wordlist=password.lst --rules mypasswd

# Incremental mode
./john --incremental hashFile

# Loopback attack (password are taken from the potfile)
./john --loopback hashFile

# Mask bruteforce attack
./john --mask=?1?1?1?1?1?1 --1=[A-Z] hashFile --min-len=8

# Dictionnary attack using masks
./john --wordlist=password.lst -mask='?l?l?w?l' hashFile
```
## Misc & Tricks
```
# Show hidden options
./john --list=hidden-options

# Using session and restoring them
./john hashes --session=name
./john --restore=name
./john --session=allrules --wordlist=all.lst --rules mypasswd &
./john status

# Show the potfile
./john hashes --pot=potFile --show

# Search if a root/uid0 have been cracked
john --show --users=0 mypasswdFile
john --show --users=root mypasswdFile
```
```
# List OpenCL devices and get their id
./john --list=opencl-devices

# List format supported by OpenCL
./john --list=formats --format=opencl

# Using multiples GPU
./john hashes --format:openclformat --wordlist:wordlist --rules:rules --dev=0,1 --fork=2

# Using multiple CPU (eg. 4 cores)
./john hashes --wordlist:wordlist --rules:rules --dev=2 --fork=4
```
## Wordlists & Incremental 
```
# Sort a wordlist for the wordlist mode
tr A-Z a-z < SOURCE | sort -u > TARGET

# Use a potfile to generate a new wordlist
cut -d ':' -f 2 john.pot | sort -u pot.dic

# Generate candidate password for slow hashes
./john --wordlist=password.lst --stdout --rules:Jumbo | ./unique -mem=25 wordlist.uniq
```
```
--incremental:Lower # 26 char
--incremental:Alpha # 52 char
--incremental:Digits # 10 char
--incremental:Alnum # 62 char

# Create a new charset
./john --make-charset=charset.chr

# Then set the following in the John.conf
# Incremental modes
[Incremental:charset]
File = $JOHN/charset.chr
MinLen = 0
MaxLen = 31
CharCount = 95

# Using a specific charset
./john --incremental:charset hashFile
```
## Rules
```
# Predefined rules
--rules:Single
--rules:Wordlist
--rules:Extra
--rules:Jumbo # All the above
--rules:KoreLogic
--rules:All # All the above
```
```
# Create a new rule in John.conf
[List.Rules:Tryout]
l
u
...
```
```
| Rule          | Description                                               |
|------------   |-------------------------------------------------------    |
| l             | Convert to lowercase                                      |
| u             | Convert to uppercase                                      |
| c             | Capitalize                                                |
| l r           | Lowercase the word and reverse it                         |
| l Az"2015"    | Lowercase the word and append "2015" at the end           |
| d             | Duplicate                                                 |
| l A0"2015"    | Lowercase the word and append "2015" at the beginning     |
| A0"#"Az"#"    | Add "#" at the beginning and the end of the word          |
| C             |  Lowercase the first char and uppercase the rest          |
| t             | Toggle case of all char                                   |
| TN            | Toggle the case of the char in position N                 |
| r             | Reverse the word                                          |
| f             | Reflect (Fred --> Fredderf)                               |
| {             | Rotate the word left                                      |
| }             | Rotate the word right                                     |
| $x            | Append char X to the word                                 |
| ^x            | Prefix the word with X char                               |
| [             | Remove the first char from the word                       |
| ]             | Remove the last char from the word                        |
| DN            | Delete the char in position N                             |
| xNM           | Extract substring from position N for M char              |
| iNX           | Insert char X in position N and shift the rest right      |
| oNX           | Overstrike char in position N with X                      |
| S             | Shift case                                                |
| V             | Lowercase vowels and uppercase consonants                 |
| R             | Shift each char right on the keyboard                     |
| L             | Shift each char left on the keyboard                      |
| <N            | Reject the word unless it is less than N char long        |
| >N            | Reject the word unless it is greater than N char long     |
| \'N           | Truncate the word at length N                             |
```

## Crack a Steg image Password Protected
```
$ stegseek image.jpg
```
```
$ stegcracker image.jpg
```

## Crack a password Protected zip file
```
$ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip
```
```
$ zip2john file.zip > hash
$ john -w=/usr/share/wordlists/rockyou.txt hash
```

## Crack a password Protected RAR file
```bash
$ rar2john file.rar > hash
$ john -w=/usr/share/wordlists/rockyou.txt hash
```

## Cracking shadow files
```bash
unshadow passwd shadow > shadowjohn.txt
john -wordlist=/usr/share/wordlists/rockyou.txt --rules shadowjohn.txt
john --show shadowjohn.txt

# Hashcat SHA512 $6$ shadow file  
hashcat -m 1800 -a 0 hash.txt rockyou.txt --username

#Hashcat MD5 $1$ shadow file  
hashcat -m 500 -a 0 hash.txt rockyou.txt --username
```

## Various cracking techniques
```bash
# Hashcat MD5 Apache webdav file  
hashcat -m 1600 -a 0 hash.txt rockyou.txt

# Hashcat SHA1  
hashcat -m 100 -a 0 hash.txt rockyou.txt --force

# Hashcat Wordpress  
hashcat -m 400 -a 0 --remove hash.txt rockyou.txt

# SSH Key
ssh2john id_rsa  > sshtocrack
john --wordlist=/usr/share/wordlists/rockyou.txt sshtocrack

# Cracking Cisco passwords
# Type 5 → MD5
# Type 7 → Easy reversible
hashcat -m 500 c:\temp\ciscohash.txt C:\DICS\english-dic.txt

# Cracking NTLVMv2 hashes
john --format=netntlmv2 --wordlist="/usr/share/wordlists/rockyou.txt" hash.txt 
```

## Cracking TGS
```bash
# Using John from bleeding repo:


./john --w=/usr/share/wordlists/rockyou.txt --fork=4 --format=krb5tgs /home/user/kerberos_hashes.txt
```

# Wordlists
```bash
https://github.com/kaonashi-passwords/Kaonashi
https://github.com/tarraschk/richelieu
https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
https://packetstormsecurity.com/Crackers/wordlists/page4/
http://www.gwicks.net/dictionaries.htm

# SCADA Default Passwords
http://www.critifence.com/default-password-database/

https://weakpass.com/
https://github.com/berzerk0/Probable-Wordlists

# Looks very cool wordlists
https://github.com/FlameOfIgnis/Pwdb-Public
```
## CewL
```bash
# CeWL allows you to build custom wordlists based on online resources
# If you know that your target is target.com, you can parse web content to build lists
# Can be time consuming

# 5 levels of depth and minimum 7 char per word
cewl -w customwordlist.txt -d 5 -m 7 www.sans.org

# Also visit and parse other sites
cewl -w customwordlist.txt -d 5 -m 7 -o www.sans.org

# Include e-mail adresses
cewl -w customwordlist.txt -d 5 -m 7 -e www.sans.org
```
## Combinator
```bash
# Combinator is part of the hashcat-utils
# It can be used to prepare a combinated wordlist for cracking
# It allows then to combination + others settings like masks or rules
combinator.exe file1 file2

# It can create MASSIVE wordlists and take some time to run.

# Three files combination
combinator2.exe file1 file2 file3

# You can also feed output directly to hashcat
combinator.exe file1 file2 | hashcat -m x hashs.file -a 0 --force -O
```

# Lestat
```bash
https://github.com/astar-security/Lestat
# Great tool by Astar Security, multiple scripts for extraction, parsing and creating wordlists...

# Wiki is also cool to get informations about the different prerequisites and tools
https://github.com/astar-security/Lestat/wiki
```
```bash
# LesterTheLooter cna be used to get data about cracked passwords
# - the list of the domain groups of each craked account
# - an indicator about whether a cracked account is admin or not
# - the status of each cracked account: ACCOUNT_DISABLED or ACCOUNT_ENABLED
# - the list of all the domain groups compromised through the cracked accounts 
#   (no false positive due to disabled users)
# - a comprehensive set of stats about the passwords cracked
#   (length distribution, charset, robustness evaluation, most frequent pattern, ...)

python3 LesterTheLooter.py --priv JOHN_RESULT.txt USERS_INFO.txt
[*] Importing john result from JOHN_RESULT.txt and domain info from USERS_INFO.txt
[!] Line ignored in JOHN_RESULT.txt file (not a valid user:password form): 
[!] Line ignored in JOHN_RESULT.txt file (not a valid user:password form): 124 password hashes cracked, 589 left
[*] Computing groups information
[*] Exporting data to users_compromised.csv and group_compromised.csv
[*] Privileged accounts compromised are listed below:
[+] disabled     domain admins        n.sarko                  Cecilia<3
[+] enabled      likely admin         f.maçon                  NOMondial2020!
[+] enabled      enterprise admins    adm.boloré               Y4tch4life
[+] enabled      domain admins        e.macron                 Macron2022!!!
[+] enabled      enterprise admins    b.gates                  VaccineApple!
[+] disabled     account operators    e.philippe               Prosac2k19

# Get some stats in addition of the CSV files
python3 LesterTheLooter.py --stats JOHN_RESULT.txt USERS_INFO.txt

# You can get comprehensive stats if you configured the wordlists :
python3 LesterTheLooter.py --wordlists <PATH_TO_WORDLISTS> --stats JOHN_RESULT.txt USERS_INFO.txt
```
```bash
# Check for leaked NTLM
# Look for presence of users in the HaveIBeenPwned list:

python3 LesterTheLooter.py --verbose <HASHES_FILE> <HAVEIBEENPWNED_LIST>
```
