/*
 * ** dnsmap - DNS Network Mapper by pagvac
 * ** Copyright (C) 2009 gnucitizen.org
 * **
 * ** This program is free software; you can redistribute it and/or modify
 * ** it under the terms of the GNU General Public License as published by
 * ** the Free Software Foundation; either version 2 of the License, or
 * ** (at your option) any later version.
 * **
 * ** This program is distributed in the hope that it will be useful,
 * ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 * ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * ** GNU General Public License for more details.
 * **
 * ** You should have received a copy of the GNU General Public License
 * ** along with this program; if not, write to the Free Software
 * ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dnsmap.h" // built-in subdomains list and define macros


// function prototypes
unsigned short int wildcarDetect(char *, char *);
unsigned short int dodelay(unsigned short int);
unsigned short int isPrivateIP(char *);
unsigned short int isValidDomain(char *);
unsigned short int usesOpenDNS(char *);
unsigned short int isIPblacklisted(char *);

int main(int argc, char *argv[]) {

	unsigned short int i=0, j=0, k=0, l=0, found=0, ipCount=0, milliseconds=0, intIPcount=0,
		wordlist=FALSE, results=FALSE, csvResults=FALSE, delay=FALSE;
	unsigned long int start=0, end=0;
	char dom[MAXSTRSIZE]={'\0'}, csvResultsFilename[MAXSTRSIZE]={'\0'}, 
		txtResultsFilename[MAXSTRSIZE]={'\0'}, wordlistFilename[MAXSTRSIZE]={'\0'},
		ipstr[INET_ADDRSTRLEN]={'\0'}, falsePosIpstr[INET_ADDRSTRLEN]={'\0'},
		invalidTldIpstr[INET_ADDRSTRLEN]={'\0'};
	void *addr;
	char *ipver;

	struct hostent *host;
	// start of IPv6 stuff
    	struct addrinfo hints, *res, *p;
    	int status;
    	char ipv6str[INET6_ADDRSTRLEN];
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET6; // AF_INET or AF_INET6 to force version
        hints.ai_socktype = SOCK_STREAM;
	// end of IPv6 stuff

	FILE *fpWords,*fpCsvLogs,*fpTxtLogs;

	time_t     now;
	struct tm  *ts;
	char       timestampBuf[18];
 
	printf("%s", BANNER);

	/* Get the current time */
	now = time(NULL);
	 
	/* timestamp format, "yyyy_mm_dd_hhmmss" */
	ts = localtime(&now);
	strftime(timestampBuf, sizeof(timestampBuf), "%Y_%m_%d_%H%M%S", ts);


	// start of *primitive* input validation
	// ideally more work should be spent on this!
	if(argc==1) {
		printf("%s%s", USAGE, EXAMPLES);	
		exit(1);	
	}
	else if(argc%2==1 && argc>2) {
		printf("%s%s", USAGE, EXAMPLES);	
		exit(1);	
	}
	if(!isValidDomain(argv[1])) {
		printf("%s", DOMAINERR);	
		exit(1);
	}

	for(i=0;i<argc;++i) {
		if((strlen(argv[i]))>MAXSTRSIZE) {
			printf("%s",INPUTERR);                        
			exit(1);
		}
	}
	// end of simple input validation
	
	/*
	else if ((h=gethostbyname(argv[1])) == NULL) {  // get the host info
	        herror("gethostbyname");
	        exit(1);
	}
	*/
	
	//printf("%s", BANNER);

	start=(int)time(NULL);

	#if DEBUG
		printf("start time: %d\n", (int)start);
	#endif

	// parse options
	for(i=0;i<argc;++i) { 
		// save results in file using regular format	
		if(!strcmp(argv[i],"-r")) {	
	       		// contruct path where txt results file will be created 
			results=TRUE;	
			//strncpy(csvResultsFilename, argv[(i+1)], MAXSTRSIZE);
			strncpy(txtResultsFilename, argv[(i+1)], MAXSTRSIZE-strlen(txtResultsFilename)-1);	
			fpTxtLogs=fopen(txtResultsFilename, "a");
			if(!fpTxtLogs) {
				strncat(txtResultsFilename, "dnsmap_", MAXSTRSIZE-strlen(txtResultsFilename)-1);
				strncat(txtResultsFilename, argv[1], MAXSTRSIZE-strlen(txtResultsFilename)-1);
				strncat(txtResultsFilename, "_", MAXSTRSIZE-strlen(txtResultsFilename)-1);
				strncat(txtResultsFilename, timestampBuf, MAXSTRSIZE-strlen(txtResultsFilename)-1);
				// replace dots '.' with underscores '_' in filename
				for(l=0;l<strlen(txtResultsFilename);++l)
					if(txtResultsFilename[l]=='.')
						txtResultsFilename[l]='_';
				strncat(txtResultsFilename, ".txt", MAXSTRSIZE-strlen(txtResultsFilename)-1);
				fpTxtLogs=fopen(txtResultsFilename, "a");
				if(!fpTxtLogs) {
					printf(CREATEFILEERR);
					exit(1);
				}
			}
		}

		// save results in file using CSV format	
		if(!strcmp(argv[i],"-c")) {	
	       		// contruct path where csv results file will be created 
			csvResults=TRUE;	
			strncpy(csvResultsFilename, argv[(i+1)], MAXSTRSIZE-strlen(csvResultsFilename)-1);
 		 	fpCsvLogs=fopen(csvResultsFilename, "a");
			if(!fpCsvLogs) {
				strncat(csvResultsFilename, "dnsmap_", MAXSTRSIZE-strlen(csvResultsFilename)-1);
				strncat(csvResultsFilename, argv[1], MAXSTRSIZE-strlen(csvResultsFilename)-1);
				strncat(csvResultsFilename, "_", MAXSTRSIZE-strlen(csvResultsFilename)-1);
				strncat(csvResultsFilename, timestampBuf, MAXSTRSIZE-strlen(csvResultsFilename)-1);
				// replace dots '.' with underscores '_' in filename
				for(l=0;l<strlen(csvResultsFilename);++l)
					if(csvResultsFilename[l]=='.')
						csvResultsFilename[l]='_';
				strncat(csvResultsFilename, ".csv", MAXSTRSIZE-strlen(csvResultsFilename)-1);
				fpCsvLogs=fopen(csvResultsFilename, "a");
				if(!fpCsvLogs) {
					printf(CREATEFILEERR);
					exit(1);
				}
			}
		}	

		// use provided wordlist as opposed to built-in one
		if(!strcmp(argv[i],"-w")) {
			wordlist=TRUE;
			strncpy(wordlistFilename, argv[(i+1)],MAXSTRSIZE);
		}

		// delay between subdomain resolution requests
		if(!strcmp(argv[i],"-d")) {
			if(atoi(argv[(i+1)])<1) {
				printf("%s", DELAYINPUTERR);
				exit(1);
			}						
			delay=TRUE;
			milliseconds=atoi(argv[(i+1)]);
		}
	}

	// read subdomains from built-in list
	if(!wordlist) {
		// openDNS detection
		if(usesOpenDNS(invalidTldIpstr))
			printf("%s",OPENDNSMSG);

		// wildcard detection
		wildcarDetect(argv[1],falsePosIpstr);
		if(strcmp(invalidTldIpstr,falsePosIpstr))
			printf("%s",WILDCARDWARN);

		printf(BUILTINMSG);
		if(milliseconds>=1)
                	printf(DELAYMSG);	
			
		printf("%s", "\n");
		for(i=0;i<(sizeof(sub)/MAXSUBSIZE);++i) {
			// user wants delay between DNS requests?
			if(delay)
				dodelay(milliseconds);				
			strncpy(dom,sub[i],MAXSTRSIZE-strlen(dom)-1);
			strncat(dom,".",MAXSTRSIZE-strlen(dom)-1);//TEST
			strncat(dom,argv[1],MAXSTRSIZE-strlen(dom)-1);
			#if DEBUG
				printf("brute-forced domain: %s\n",dom);
			#endif

			// ipv6 code modded from www.kame.net
			status = getaddrinfo(dom, NULL, &hints, &res);
		    	if ((status=getaddrinfo(dom, NULL, &hints, &res))==0) {
				printf("%s\n", dom);
				++found;
			    	if(results)
					fprintf(fpTxtLogs, "%s\n", dom);
				if(csvResults)
					fprintf(fpCsvLogs, "%s", dom);
			    	for(p=res,k=0;p;p=p->ai_next,++k) {
					if (p->ai_family==AF_INET6) { // IPv6
				    		struct sockaddr_in6 *ipv6=(struct sockaddr_in6 *)p->ai_addr;
				    		addr = &(ipv6->sin6_addr);
				    		ipver = "IPv6";
					}
					// convert the IP to a string and print it:
					inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
			       		printf("%s address #%d: %s\n",ipver,k+1,ipv6str);
					++ipCount;
					if(results)
						fprintf(fpTxtLogs,"%s address: %s\n",ipver, ipv6str);
					if(csvResults)
						fprintf(fpCsvLogs,",%s", ipv6str);	
		    		}
				printf("%s", "\n");
				if(results)
					fprintf(fpTxtLogs,"\n");
				if(csvResults)
					fprintf(fpCsvLogs,"\n");	
	    			//freeaddrinfo(res); // free the linked list
				// ipv6 code modded from www.kame.net
			} // end of if conditional
			host=gethostbyname(dom);
			/*
					inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
			       		printf("%s address #%d: %s\n",ipver,k+1,ipv6str);
			*/
			//inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
			//inet_ntop(AF_INET,&host->h_addr_list[0],ipstr,sizeof ipstr);
			if(host && !isIPblacklisted(inet_ntoa(*((struct in_addr *)host->h_addr_list[0])))) {
			//if(host && !isIPblacklisted(ipstr)) {
				for(j=0;host->h_addr_list[j];++j) {
					// TEST!!!
					sprintf(ipstr,inet_ntoa(*((struct in_addr *)host->h_addr_list[j])),"%s");
					if(strcmp(falsePosIpstr,ipstr)) {
						if(j==0) {
							++found;
							printf("%s\n", dom);
						
						    	if(results)
								fprintf(fpTxtLogs, "%s\n", dom);
							if(csvResults)
								fprintf(fpCsvLogs, "%s", dom);
						}
						printf("IP address #%d: %s\n", j+1,ipstr);
						++ipCount;
					//}
						//printf("IP address #%d: %s\n", j+1, 
						//	inet_ntoa(*((struct in_addr *)host->h_addr_list[j])));
						// TEST!!
						if(isPrivateIP(ipstr)) {
						//if(isPrivateIP(inet_ntoa(*((struct in_addr *)host->h_addr_list[j])))) {
							printf("%s",INTIPWARN);
							++intIPcount;						
						}
						if(!strcmp(ipstr,"127.0.0.1") && strcmp(falsePosIpstr,ipstr)) {	
						//if(!strcmp(inet_ntoa(*((struct in_addr *)host->h_addr_list[j])),
							//"127.0.0.1"))
							printf("%s",SAMESITEXSSWARN);
						}
						if(results) {
							//fprintf(fpCsvLogs,",%s",
							//	inet_ntoa(*((struct in_addr *)host->h_addr_list[j])));	
							fprintf(fpTxtLogs,"IP address #%d: %s\n", j+1, ipstr);
							if(isPrivateIP(ipstr) && strcmp(falsePosIpstr,ipstr))
								fprintf(fpTxtLogs,"%s",INTIPWARN);
							if(!strcmp(ipstr,"127.0.0.1") && strcmp(falsePosIpstr,ipstr))
								fprintf(fpTxtLogs,"%s",SAMESITEXSSWARN);
						}
						if(csvResults && strcmp(falsePosIpstr,ipstr))
							fprintf(fpCsvLogs,",%s",ipstr);
					}	
				}	
				if(strcmp(falsePosIpstr,ipstr))				
					printf("%s", "\n");
				if(results && strcmp(falsePosIpstr,ipstr))
					fprintf(fpTxtLogs,"%s","\n");
				if(csvResults && strcmp(falsePosIpstr,ipstr))
					fprintf(fpCsvLogs,"%s","\n");
			}
  
		}
		if(results)
			fclose(fpTxtLogs);
		if(csvResults)
			fclose(fpCsvLogs);	
	}
	
	// read subdomains from wordlist file	
	else if(wordlist) {
      		// openDNS detection
		if(usesOpenDNS(invalidTldIpstr))
			printf("%s",OPENDNSMSG);

		// wildcard detection
		wildcarDetect(argv[1],falsePosIpstr);
		if(strcmp(invalidTldIpstr,falsePosIpstr))
			printf("%s",WILDCARDWARN);

		fpWords=fopen(wordlistFilename, "r");	
		if(fpWords) { 
			printf(EXTERNALMSG);
			if(milliseconds>=1)
	                	printf(DELAYMSG);
			printf("%s","\n");
	
                        while(!feof(fpWords)) {
				strncpy(dom,"",MAXSTRSIZE-strlen(dom)-1);
				// user wants delay between DNS requests?
				if(delay)
					dodelay(milliseconds);
				fscanf(fpWords,"%s",dom); 
				if(!strcmp(dom, ""))
					break;
                                strncat(dom,".",MAXSTRSIZE-strlen(dom)-1);
                                strncat(dom,argv[1],MAXSTRSIZE-strlen(dom)-1);
				#if DEBUG
					printf("brute-forced domain: %s\n",dom);
				#endif
				// ipv6 code modded from www.kame.net
				status = getaddrinfo(dom, NULL, &hints, &res);
			    	if ((status=getaddrinfo(dom, NULL, &hints, &res))==0) {
					printf("%s\n", dom);
					++found;
				    	if(results)
						fprintf(fpTxtLogs, "%s\n", dom);
					if(csvResults)
						fprintf(fpCsvLogs, "%s", dom);
				    	for(p=res,k=0;p;p=p->ai_next,++k) {
						void *addr;
						char *ipver;
						if (p->ai_family==AF_INET6) { // IPv6
					    		struct sockaddr_in6 *ipv6=(struct sockaddr_in6 *)p->ai_addr;
					    		addr = &(ipv6->sin6_addr);
					    		ipver = "IPv6";
						}
						// convert the IP to a string and print it:
						inet_ntop(p->ai_family, addr, ipv6str, sizeof ipv6str);
				       		printf("%s address #%d: %s\n",ipver,k+1,ipv6str);
						++ipCount;
						if(results)
							fprintf(fpTxtLogs,"%s address: %s\n",ipver, ipv6str);
						if(csvResults)
							fprintf(fpCsvLogs,",%s", ipv6str);	
			    		}
					printf("%s", "\n");
					if(results)
						fprintf(fpTxtLogs,"\n");
					if(csvResults)
						fprintf(fpCsvLogs,"\n");	

		    			//freeaddrinfo(res); // free the linked list
					// ipv6 code modded from www.kame.net
				} // end of if conditional

				host=gethostbyname(dom);

				if(host && !isIPblacklisted(inet_ntoa(*((struct in_addr *)host->h_addr_list[0])))) {
                                        for(j=0;host->h_addr_list[j];++j) {
						sprintf(ipstr,inet_ntoa(*((struct in_addr *)host->h_addr_list[j])),"%s");	                                        
						if(strcmp(falsePosIpstr,ipstr)) {
							if(j==0) {
								++found;
								printf("%s\n",dom);

						               if(results) {
						                        //fprintf(fpCsvLogs,"%s",dom);
									fprintf(fpTxtLogs,"%s\n",dom);
								}
						                if(csvResults) {
						                        //fprintf(fpCsvLogs,"%s",dom);
									fprintf(fpCsvLogs,"%s",dom);
								}
							}
							printf("IP address #%d: %s\n",j+1,ipstr);
							++ipCount;
						}

						//printf("IP address #%d: %s\n",j+1,
						//	inet_ntoa(*((struct in_addr *)host->h_addr_list[j])));
						if(isPrivateIP(ipstr) && strcmp(falsePosIpstr,ipstr)) {
							printf("%s",INTIPWARN);
							++intIPcount;						
						}
						if(!strcmp(ipstr,"127.0.0.1") && strcmp(falsePosIpstr,ipstr))
							printf("%s",SAMESITEXSSWARN);
	                                        if(results && strcmp(falsePosIpstr,ipstr)) {
							fprintf(fpTxtLogs,"IP address #%d: %s\n",j+1,ipstr);
							if(isPrivateIP(ipstr))
								fprintf(fpTxtLogs,"%s",INTIPWARN);
							if(!strcmp(ipstr,"127.0.0.1"))
								fprintf(fpTxtLogs,"%s",SAMESITEXSSWARN);
						}
						if(csvResults && strcmp(falsePosIpstr,ipstr))
							fprintf(fpCsvLogs,",%s",ipstr);	
                                        }
					if(strcmp(falsePosIpstr,ipstr)) {
							printf("%s", "\n");
		                                if(results)
							fprintf(fpTxtLogs,"%s","\n");
						if(csvResults)
		                                        fprintf(fpCsvLogs,"%s","\n");
					}
                                }
			}
			fclose(fpWords);
		}
		else {
			printf(OPENFILEERR);
			exit(1);
		}
		if(results) {
			fclose(fpCsvLogs);	
			fclose(fpTxtLogs);
		}
	}

	printf(RESULTSMSG4);
	if(intIPcount>=1)
		printf(RESULTSMSG1);

	if(results)
		printf(RESULTSMSG2);
	if(csvResults)
		printf(RESULTSMSG5);	

	end=(int)time(NULL);
	printf(RESULTSMSG3);

	return 0;
}

// return true if domain wildcards are enabled
unsigned short int wildcarDetect(char *dom, char *ipstr) {
        char strTmp[30]={'\0'},s[MAXSTRSIZE]={'\0'};
        unsigned short int i=0,n=0,max=0;
	struct hostent *h;

        srand(time(NULL));
	max=rand()%20;
	// max should be between 10 and 20
	if(max<10)
		max=max+(10-max);
	
	// generate up to random 20 digits-long subdomain
	// e.g. 06312580442146732554
 
	for(i=0;i<max;++i) {
                n=rand()%10;
                sprintf(strTmp, "%d", n);
                if(i==0)
                        strncpy(s,strTmp,MAXSTRSIZE-strlen(s)-1);
                else
                        strncat(s,strTmp,MAXSTRSIZE-strlen(s)-1);
        }
	strncat(s,".",MAXSTRSIZE-strlen(s)-1);
	strncat(s, dom,MAXSTRSIZE-strlen(s)-1);
	#if DEBUG
		printf("random subdomain for wildcard testing: %s\n",s);
	#endif
	
	// random subdomain resolves, thus wildcards are enabled
	h=gethostbyname(s);
	if(h) {
		for(i=0;h->h_addr_list[i];++i) {
			sprintf(ipstr,inet_ntoa(*((struct in_addr *)h->h_addr_list[i])),"%s");	                                  
			#if DEBUG
				printf("wildcard domain\'s IP address #%d: %s\n",i+1,ipstr);
			#endif
		}
		return TRUE;

	}
	else
		return FALSE;
}

// return number of milliseconds delayed
unsigned short int dodelay(unsigned short int maxmillisecs) {
	unsigned short int n=0;

	srand(time(NULL));
	n=rand()%maxmillisecs;
	++n;
	maxmillisecs=n;
	#if DEBUG
		printf("sleeping %d milliseconds ...\n",maxmillisecs);
	#endif
	usleep(maxmillisecs*1000);

	return maxmillisecs;
}

// return true if IP addr is internal (RFC1918)
unsigned short int isPrivateIP(char *ip) {
	
  	char classB[][8]={"172.16.","172.17.","172.18.","172.19.",
		"172.20.","172.21.","172.22.","172.23.","172.24.",
		"172.25.","172.26.","172.27.","172.28.","172.29.",
		"172.30.","172.31."};

	unsigned short int i=0,j=0;
	size_t len = strlen(ip);

	// shortest: 0.0.0.0 - 8 chars inc \0
	// longest: 255.255.255.255 - 16 chars inc \0
	if(len<8 || len>16)
		return 0;
	// ip addr must have three period signs
	for(i=0,j=0;i<len;++i) {
		if(ip[i]=='.')
			++j;
	}
	if(j!=3 || ip[0]=='.' || ip[len-1]=='.')
		return 0;

	// 10.0.0.0 - 10.255.255.255 (10/8 prefix)
	if(strncmp(ip,"10.",3)==0)
		return 1;

	// 192.168.0.0 - 192.168.255.255 (192.168/16 prefix)
	else if(strncmp(ip,"192.168.",8)==0)
		return 1;
	
	
	else {
		// 172.16.0.0 - 172.31.255.255  (172.16/12 prefix)		
		for(i=0;i<sizeof(classB)/8;++i) {
			if(strncmp(ip,classB[i],7)==0)
				return 1;
		}
		return 0;
	}
}

// return true if domain is valid, false otherwise
unsigned short int isValidDomain(char *d) {

	unsigned int i=0;
	char *tld;
	size_t len;

	if(strlen(d)<4) // smallest possible domain provided. e.g. a.pl
		return 0;
	if(!strstr(d,".")) // target domain must have at least one dot. e.g. target.va, branch.target.va
		return 0;
        tld=strstr(d,".");
        tld=tld+1;
	while(strstr(tld,".")){
		tld=strstr(tld,".");	
		tld=tld+1;
	}
	#if DEBUG
		printf("tld\'s length: %d\n",strlen(tld));
		printf("dom: %s tld: %s\n",d,tld);
	#endif
	if((strlen(tld)<2) || (strlen(tld)>6)) // tld must be between 2-6 char. e.g. .museum, .uk
		return 0;

	// valid domain can only contain digits, letters, dot (.) and dash symbol (-)
	len = strlen(d);
	for(i=0;i<len;++i) {
		if (!(d[i] >= '0' && d[i] <= '9') &&
			!(d[i] >= 'a' && d[i] <= 'z') &&
			!(d[i] >= 'A' && d[i] <= 'Z') &&
			!(d[i] >= '-' && d[i] <= '.'))
			return 0;
	}

	return 1;

}

// return true if IP is blacklisted, false otherwise
unsigned short int isIPblacklisted(char *ip) {
	int i;
	// add you own blacklisted IP addresses here if dnsmap is producing false positives.
	// this could be caused by your ISP returning a captive portal search page when
	// when requesting invalid domains on your browser
	char ips[][INET_ADDRSTRLEN]={
					"81.200.64.50",
					"67.215.66.132",
					"1.2.3.4"	// add your false positive IPs here
					};

	//for(i=0;ips[i];++i) {
	for(i=0;i<(sizeof(ips)/INET_ADDRSTRLEN);++i) {
		if(!strcmp(ips[i],ip))
			return TRUE;
	}

	return FALSE;
}


// return true if usage of public DNS server is detected
// Note: right now this function only detects openDNS, but might be 
// updated in the future to detect other common public DNS servers
unsigned short int usesOpenDNS(char *ipstr) {
        char strTmp[30]={'\0'}, s[MAXSTRSIZE]={'\0'}, dummyLTD[4]={"xyz"}/*, ipstr[INET_ADDRSTRLEN]={'\0'}*/;
	char ips[][INET_ADDRSTRLEN]={"67.215.65.132"};
        unsigned short int i=0,j=0,n=0,max=0;
	struct hostent *h;

        srand(time(NULL));
	max=rand()%20;
	// max should be between 10 and 20
	if(max<10)
		max=max+(10-max);
	
	// generate up to random 20 digits-long subdomain
	// e.g. 06312580442146732554
 
	for(i=0;i<max;++i) {
                n=rand()%10;
                sprintf(strTmp, "%d", n);
                if(i==0)
                        strncpy(s,strTmp,MAXSTRSIZE-strlen(s)-1);
                else
                        strncat(s,strTmp,MAXSTRSIZE-strlen(s)-1);
        }
	strncat(s,".",MAXSTRSIZE-strlen(s)-1);
	strncat(s, dummyLTD,MAXSTRSIZE-strlen(s)-1);
	#if DEBUG
		printf("random domain for public DNS testing: %s\n",s);
	#endif
	
	// random invalid domain resolves, thus public DNS in use
	h=gethostbyname(s);
	if(h) {
		for(i=0;h->h_addr_list[i];++i) {
			sprintf(ipstr,inet_ntoa(*((struct in_addr *)h->h_addr_list[i])),"%s");	                                  
			#if DEBUG
				printf("public DNS server\'s default IP address #%d: %s\n",i+1,ipstr);
			#endif
			for(j=0;i<(sizeof(ips)/INET_ADDRSTRLEN);++j) {
					if(!strcmp(ips[i],ipstr))
						return TRUE;
			}
		}
		return TRUE;
	}
	else
		return FALSE;
}
