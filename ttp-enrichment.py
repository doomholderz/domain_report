from tld import get_tld
import math
from Levenshtein import distance

def breakdown_domain(domain):
	# i.e. breakdown of twetter.account-management.f53dw.io results in
	# innerdomain = "f53dw"
	# subdomain = ["twetter", "account-management"]
	# tld = "io"
	domain_parts = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
	subdomain = domain_parts.subdomain.split(".")
	domain = {"domain": '.'.join([domain_parts.domain, domain_parts.subdomain]), "innerdomain": domain_parts.domain, "subdomains": subdomain, "tld": domain_parts.tld}
	return domain

def entropy(domain):
    prob = [ float(domain.count(i)) / len(domain) for i in dict.fromkeys(list(domain))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def lev_distance(domain):
	suspicious = open('suspicious.txt', 'r')
	impersonating_words = []
	found_words = []
	lev_return = {"impersonating": [], "matching": []}
	for item in suspicious:
		for word in domain:
			#print(word + " " + item + " " + str(distance(str(word), str(item))))
			if distance(str(word), str(item)) == 2:
				#print(word + " impersonating word " + item)
				impersonating_words.append(word)
			elif distance(str(word), str(item)) <= 1:
				#print(word + " matches " + item)
				found_words.append(word)
	lev_return['impersonating'] = impersonating_words
	lev_return['matching'] = found_words
	return lev_return

def main(domain):
	domain = breakdown_domain(example_domain)
	domain_entropy = entropy(domain['domain'])
	domain_enrichment_obj = {"domain": domain, "domainEntropy": domain_entropy}
	print(domain['subdomains'])
	subdomain_lev = lev_distance(domain['subdomains'])
	domain_lev = lev_distance(domain['domain'])
	domain_enrichment_obj['levDistance'] = {"innerDomain": domain_lev, "subdomains": subdomain_lev}
	return domain_enrichment_obj

example_domain = "twetter.account-management.f53dw.io"
print(main(example_domain))
