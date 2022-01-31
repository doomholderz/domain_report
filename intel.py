from ttpenrichment import *
from censyslookup import *
from domainregistration import *
import os
import re

# use this for tidying up the shop
def clear_console():
    command = 'clear'
    if os.name in ('nt', 'dos'): 
        command = 'cls'
    os.system(command)

def main():
	clear_console()
	domain = input("Enter domain to gather intel on: ")

	# checks the inputted domain is in the correct format
	if re.search("^[a-z0-9]([a-z0-9-]+\.){1,}[a-z0-9]+\Z", domain) == None:
		input("Incorrect value for domain name.\n[RETURN]")
		main()

	clear_console()
	print("Gathering intel for " + domain + "\n")

	# keep asking for options until a correct set of options are presented
	while True:
		options = get_options()
		if options != None:
			break

	# for each of these options, we need to run a different script
	for option in options:
		if int(option) == 1:
			clear_console()

			# grab the censys app ID and secret from the user to use
			censys_id = input("Please [ENTER] Censys App ID: ")
			censys_secret = input("Please [ENTER] Censys App Secret: ")

			# need to identify if api key is for free or paid account, as rate limits vary
			while True:
				censys_limit = get_censys_creds()
				if censys_limit != None:
					break

			# now we run the ip and subdomain scripts using censys account and limit info
			ips_obj = ips(domain, censys_id, censys_secret)
			subdomain_obj = subdomains(domain, censys_id, censys_secret, censys_limit)
			return_obj['censysLookup']['subdomains'] = subdomain_obj
			return_obj['censysLookup']['ips'] = ips_obj
	
		# if domain enrichment picked, we need to quickly get tld as its a parameter in the functions
		elif int(option) == 2:
			tld = breakdown_domain(domain)['tld']
			rdap_obj = rdap(domain, tld)
			return_obj['domainEnrichment'] = rdap_obj
	
		# if it's ttp enrichment picked, we can just go ahead and run the script
		elif int(option) == 3:
			ttp_obj = main(domain)
			return_obj['ttpEnrichment'] = ttp_obj

# function for checking the user-picked options are valid
def get_options():
	options = input("Enter intel choice (comma-separated for multiple choices):\n1. Censys Lookup (related IPs and subdomains)\n2. Domain registration records\n3. TTP-based enrichment\n")
	options_array = []
	for option in options.split(","):
		option = option.strip()
		if option not in ["1", "2", "3"]:
			print("Incorrect options choice")
			return None
		else:
			options_array.append(option)
	return options_array

# function for checking what sort of API key has been provided, then setting the limit appropriately
def get_censys_creds():
	clear_console()
	censys_limit_q = input("Are you using (1) a paid API key, or (2) a free API key?: ")
	if censys_limit_q == "1":
		censys_limit = 1000
	elif censys_limit_q == "2":
		censys_limit = 50
	else:
		input("Incorrect option for API Key, must be 1 or 2\n[RETURN]")
		return None
	return censys_limit

main()
