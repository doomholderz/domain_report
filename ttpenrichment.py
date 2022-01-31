from tld import get_tld
import math
from Levenshtein import distance
import re

# breakdown_domain: breakdown of twetter.account-management.f53dw.io results in
# innerdomain = "f53dw"
# subdomain = ["twetter", "account-management"]
# tld = "io"
def breakdown_domain(domain):
	# use get_tld with all the params it needs to hum along
	domain_parts = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
	
	# break subdomain into an array of its components (i.e. a.x.y = ["a", "x", "y"])
	subdomain = domain_parts.subdomain.split(".")
	
	# create domain object with all components derived from get_tld
	domain = {"domain": '.'.join([domain_parts.domain, domain_parts.subdomain]), "innerdomain": domain_parts.domain, "subdomains": subdomain, "tld": domain_parts.tld}
	return domain

# shannon entropy to calculate entropy of full domain (high entropy typically
# is associated with more malicious domains)
def entropy(domain):
    prob = [ float(domain.count(i)) / len(domain) for i in dict.fromkeys(list(domain))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

# levenshtein distance, finding words that match/closely impersonate other words
# typical of domains to impersonate other domains (i.e. twetter instead of twitter)
def lev_distance(domain):
	# grab words we want to find matches/impersonations against from suspicious.txt
	suspicious = open('suspicious.txt', 'r')
	
	# we will be returning an object of impersonating/matching words
	lev_return = {"impersonating": [], "matching": []}
	impersonating_words = []
	found_words = []
	
	for item in suspicious:
		for word in domain:

			# distance == 2 typically means one letter out (i.e. paypol)
			if distance(str(word), str(item)) == 2:
				impersonating_words.append(word)

			# distance <= 1 typically means a bang-on match
			elif distance(str(word), str(item)) <= 1:
				found_words.append(word)

	# assign impersonating/matching arrays to the lev_return object, and return
	lev_return['impersonating'] = impersonating_words
	lev_return['matching'] = found_words
	return lev_return

# searches for usage of tld strings within domain/subdomains, as this is spoopy
def fake_tlds(domain_array):
	fake_tlds_array = []

	# iterate over the domain/subdomain array parameter
	for string in domain_array:

		# split string based on non A-Z characters (i.e. test.y-a = ['test', 'y', 'a'])
		for word in re.split("\W+", string):

			# if the word is one of these TLDs, append to the array
			# could absract this list to a .txt file, but can I be bothered
			if word in ['com', 'co', 'uk', 'net', 'org', 'io']:
				fake_tlds_array.append(word)

	return fake_tlds_array

def ttp_main(example_domain):
	# initialize the object that will store all enrichment, and be returned 
	domain_enrichment_obj = {}

	# breakdown the domain into its components (domain, subdomains, innerdomain, tld)
	domain = breakdown_domain(example_domain)
	domain_enrichment_obj['domain'] = domain

	# get the entropy of the overall domain
	domain_entropy = entropy(domain['domain'])
	domain_enrichment_obj['domainEntropy'] = domain_entropy

	# get impersonating/matching words in domain and subdomains
	subdomain_lev = lev_distance(domain['subdomains'])
	domain_lev = lev_distance(domain['innerdomain'])
	domain_enrichment_obj['levDistance'] = {"innerDomain": domain_lev, "subdomains": subdomain_lev}
	
	# get tlds nested within inner domain/subdomains
	subdomain_tlds = fake_tlds(domain['subdomains'])
	domain_tlds = fake_tlds([domain['innerdomain']])
	domain_enrichment_obj['fakeTlds'] = {"innerDomain": domain_tlds, "subdomains": subdomain_tlds}

	# finally we can return the domain enrichment object with all data within
	return domain_enrichment_obj

#example_domain = "twetter.account-management-com.f53dw-net.io"
#print(main(example_domain))
