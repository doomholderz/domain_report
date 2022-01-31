from ttpenrichment import *
from censyslookup import *
from domainregistration import *
import os

def clearConsole():
    command = 'clear'
    if os.name in ('nt', 'dos'): 
        command = 'cls'
    os.system(command)

clearConsole()
domain = input("Enter domain to gather intel on: \n")
clearConsole()

print("Gathering intel for " + domain + "\n")
options = input("Enter intel choice (comma-separated for multiple choices):\n1. Censys Lookup (related IPs and subdomains)\n2. Domain registration records\n3. TTP-based enrichment\n")

clearConsole()

return_obj = {}

for option in options.split(","):
	
	option = option.strip()
	if option not in ["1","2","3"]:
		print("Incorrect options choice")
		break

	if int(option) == 1:
		censys_id = input("Please [ENTER] Censys App ID: ")
		censys_secret = input("Please [ENTER] Censys App Secret: ")
		censys_limit_q = input("Are you using (1) a paid API key, or (2) a free API key?: ")
		if censys_limit_q == "1":
			censys_limit = 1000
		elif censys_limit == "2":
			censys_limit = 50
		ips_obj = ips(domain, censys_id, censys_secret)
		subdomain_obj = subdomains(domain, censys_id, censys_secret, censys_limit)
		return_obj['censysLookup']['subdomains'] = subdomain_obj
		return_obj['censysLookup']['ips'] = ips_obj
	
	elif int(option) == 2:
		tld = breakdown_domain(domain)['tld']
		rdap_obj = rdap(domain, tld)
		return_obj['domainEnrichment'] = rdap_obj
	
	elif int(option) == 3:
		ttp_obj = main(domain)
		return_obj['ttpEnrichment'] = ttp_obj

clearConsole()
print(return_obj)
