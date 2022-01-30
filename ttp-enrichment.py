from tld import get_tld
import math

def breakdown_domain(domain):
	# i.e. breakdown of twetter.account-management.f53dw.io results in
	# innerdomain = "f53dw"
	# subdomain = "twetter.account-management"
	# tld = "io"
	domain_parts = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
	domain = {"domain": '.'.join([domain_parts.domain, domain_parts.subdomain]), "innerdomain": domain_parts.domain, "subdomains": domain_parts.subdomain, "tld": domain_parts.tld}
	return domain

def entropy(domain):
    prob = [ float(domain.count(i)) / len(domain) for i in dict.fromkeys(list(domain))]
    entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

example_domain = "twetter.account-management.f53dw.io"

domain = breakdown_domain(example_domain)
domain_entropy = entropy(domain['domain'])

domain_enrichment_obj = {"domain": domain, "domainEntropy": domain_entropy}

print(domain_enrichment_obj)
