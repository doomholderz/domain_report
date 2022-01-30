import censys
import requests
import arrow
import json

CENSYS_API_ID = ""
CENSYS_API_SECRET = ""
API_URL = "https://search.censys.io/api"

def subdomains(domain):
	count = 0
	params = {"query" : "parsed.names: " + domain}
	
	subdomains_obj = {}

	# get all certificates that even smell of 'domain'
	res = requests.post(API_URL + "/v1/search/certificates", json = params, auth=(CENSYS_API_ID, CENSYS_API_SECRET))
	cert_json = res.json()
	
	for cert in cert_json['results']:
		count += 1
		if count < 10:
			cert_name = cert['parsed.subject_dn'].split("CN=")[-1]
			cert2 = cert['parsed.fingerprint_sha256']
			res2 = requests.get(API_URL + "/v1/view/certificates/" + cert2, auth=(CENSYS_API_ID, CENSYS_API_SECRET))
			res2j = res2.json()
			print(str(count))
			common_name = res2j['parsed']['subject']['common_name']
			issuer = res2j['parsed']['issuer']['common_name']
			start = res2j['parsed']['validity']['start']
			end = res2j['parsed']['validity']['end']
			SAN = res2j['parsed']['extensions']['subject_alt_name']['dns_names']
			subdomains_obj[cert_name] = {}
			subdomains_obj[cert_name]['certificateStartDate'] = start
			subdomains_obj[cert_name]['certificateEndDate'] = end
			subdomains_obj[cert_name]['issuer'] = issuer
			subdomains_obj[cert_name]['domainNames'] = common_name
			
	return subdomains_obj

print(subdomains(''))
