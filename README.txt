DNSMAP README FILE

INTRODUCTION

dnsmap was originally released in back in 2006 and was inspired by the
fictional story "The Thief No One Saw" by Paul Craig, which can be found
in the book "Stealing the Network - How to 0wn the Box"

dnsmap is mainly meant to be used by pentesters during the information
gathering/enumeration phase of infrastructure security assessments. During the
enumeration stage, the security consultant would typically discover the target
company's IP netblocks, domain names, phone numbers, etc ...

Subdomain brute-forcing is another technique that should be used in the
enumeration stage, as it's especially useful when other domain enumeration
techniques such as zone transfers don't work (I rarely see zone transfers
being publicly allowed these days by the way).

If you are interested in researching stealth computer intrusion techniques,
I suggest reading this excellent (and fun) chapter which you can find for
*free* on the web:

http://www.google.com/search?q=%22The+Thief+No+One+Saw%22+%22Paul+Craig%22
http://www.syngress.com/book_catalog/249_STL_NTW/sample.pdf
http://www.ethicalhacker.net/content/view/45/2/

I'm happy to say that dnsmap was included in Backtrack 2 and 3 - although the version
included is now quite dated - and has been reviewed by the community:

http://backtrack.offensive-security.com/index.php?title=Tools
http://www.linuxhaxor.net/2007/07/14/backtrack-2-information-gathering-all-dnsmap/
http://www.darknet.org.uk/2009/03/dnsmap-022-released-subdomain-bruteforcing-tool/
http://www.gnucitizen.org/blog/new-version-of-dnsmap-out/


COMPILING

Compiling should be straightforward:

$ make

Or:

$ gcc -Wall dnsmap.c -o dnsmap


INSTALLATION

Example of manual installation:

# cp ./dnsmap /usr/local/bin/dnsmap

If you wish to bruteforce several target domains in a bulk fashion, you can use the
included dnsmap-bulk.sh script. Just copy the script to /usr/local/bin/ so you can 
call it from any location. i.e.:

# cp ./dnsmap-bulk.sh /usr/local/bin/

And set execute permissions. e.g.:

# chmod ugo+x /usr/local/bin/dnsmap-bulk.sh


LIMITATIONS

This tool won't work with target domains which use wildcards. When a domain
uses wildcards, all bruteforced subdomains will resolve to the same IP address,
which makes enumerating target servers unfeasible.

dnsmap *does* however inform the user when wildcards have been detected and suggests
choosing a different target domain.


FUN THINGS THAT CAN HAPPEN

1. Finding interesting remote access servers (i.e.: https://extranet.targetdomain.com)

2. Finding badly configured and/or unpatched servers (i.e.: test.targetdomain.com)

3. Finding new domain names which will allow you to map non-obvious/hard-to-find netblocks
   of your target organization (registry lookups - aka whois is your friend)

4. Sometimes you find that some bruteforced subdomains resolve to internal IP addresses
   (RFC 1918). This is great as sometimes they are real up-to-date "A" records which means that
   it *is* possible to enumerate internal servers of a target organization from the Internet
   by only using standard DNS resolving (as oppossed to zone transfers for instance).


USAGE

Bruteforcing can be done either with dnsmap's built-in wordlist or a user-supplied wordlist.
Results can be saved in CSV and human-readable format for further processing. dnsmap does NOT
require root privileges to be run, and should NOT be run with such privileges for security reasons.

The usage syntax can be obtained by simply running dnsmap without any parameters:

$ ./dnsmap

dnsmap 0.24 - DNS Network Mapper by pagvac (gnucitizen.org)

usage: dnsmap <target-domain> [options]
options:
-w <wordlist-file>
-r <regular-results-file>
-c <csv-results-file>
-d <delay-milliseconds>
e.g.:
dnsmap target-domain.foo
dnsmap target-domain.foo -w yourwordlist.txt -r /tmp/domainbf_results.txt
dnsmap target-fomain.foo -r /tmp/ -d 3000
dnsmap target-fomain.foo -r ./domainbf_results.txt

Example of subdomain bruteforcing using dnsmap's built-in word-list:

$ ./dnsmap targetdomain.foo

Example of subdomain bruteforcing using a user-supplied wordlist:

$ ./dnsmap targetdomain.foo -w wordlist.txt

Example of subdomain bruteforcing using the built-in wordlist and saving the results to /tmp/ :

$ ./dnsmap targetdomain.foo -r /tmp/

Since no filename was provided in the previous example, but rather only a path, dnsmap would create an unique filename which includes the current timestamp. E.g.: /tmp/dnsmap_targetdomain_foo_2009_12_15_234953.txt

Example of subdomain bruteforcing using the built-in wordlist, saving the results to /tmp/, and waiting a random maximum of 3 milliseconds between each request:

$ ./dnsmap targetdomain.foo -r /tmp/ -d 3

It is recommended to use the -d (delay in milliseconds) option in cases where dnsmap is interfering with your online experience. i.e.: killing your bandwidth

For bruteforcing a list of target domains in a bulk fashion use the bash script provided. e.g.:

$ ./dnsmap-bulk.sh domains.txt /tmp/results/


WORDLISTS

http://packetstormsecurity.org/Crackers/wordlists/dictionaries/
http://www.cotse.com/tools/wordlists1.htm


OTHER SIMILAR TOOLS - choice is freedom!

WS-DNS-BFX
http://ws.hackaholic.org/tools/WS-DNS-BFX.tgz

DNSDigger
http://www.ernw.de/download/dnsdigger.zip

Fierce Domain Scan
http://ha.ckers.org/fierce/

Desperate
http://www.sensepost.com/research_misc.html

DNSenum
http://dnsenum.googlecode.com/files/dnsenum1.2.tar.gz

ReverseRaider
http://complemento.sourceforge.net/


--
pagvac | GNUCITIZEN.org
January 2010
