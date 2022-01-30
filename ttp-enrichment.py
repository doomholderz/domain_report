from tld import get_tld

def breakdown_domain(domain):
	# i.e. breakdown of twetter.account-management.f53dw.io results in
	# innerdomain = "f53dw"
	# subdomain = "twetter.account-management"
	# tld = "io"
	domain_parts = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
	domain = {"domain": '.'.join([domain_parts.domain, domain_parts.subdomain]), "innerdomain": domain_parts.domain, "subdomains": domain_parts.subdomain, "tld": domain_parts.tld}
	return domain

example_domain = "twetter.account-management.f53dw.io"

domain = breakdown_domain(example_domain)
print(domain)