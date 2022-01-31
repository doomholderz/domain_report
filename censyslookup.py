import censys
import requests
import arrow
import json

API_URL = "https://search.censys.io/api"

def subdomains(domain, censys_id, censys_secret, censys_limit):
	# using count for rate limiting
	count = 0

	# define the query parameter used for POST request, using domain parameter
	params = {"query" : "parsed.names: " + domain}
	
	# initialise the subdomains object where all subdomain info will be stored
	subdomains_obj = {}

	# get all certificates that even smell of 'domain'
	res = requests.post(API_URL + "/v1/search/certificates", json = params, auth=(censys_id, censys_secret))
	cert_json = res.json()
	
	# for each certificate relating to '*domain*', harvest information
	for cert in cert_json['results']:
		count += 1
		if count <= censys_limit:
			try:
				print(str(count))
				# get the certificate name (subdomain), which we'll use as a key in this kv-pair
				cert_name = cert['parsed.subject_dn'].split("CN=")[-1]
			
				# get the sha256 encoded fingerprint of the certificate (used for searching)
				cert2 = cert['parsed.fingerprint_sha256']

				# censys API request to get information about this certificate
				res2 = requests.get(API_URL + "/v1/view/certificates/" + cert2, auth=(censys_id, censys_secret))
				res2j = res2.json()
			
				# harvest and store additional data pertaining to the subdomain
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
				subdomains_obj[cert_name]['san'] = SAN
			except requests.exceptions.SSLError as e:
				print("requests.exceptions.SSLError")
			
	return subdomains_obj

def ips(domain, censys_id, censys_secret):
	# initialise the ips object, where we'll store info about related ips to domain
	ips_obj = {}

	# GET request using censys to get information about the domain
	res = requests.get(API_URL + "/v2/hosts/search?q=" + domain + " and service.service_name='HTTP'", auth=(censys_id, censys_secret))
	
	# for each ip found relating to the domain
	for hit in res.json()['result']['hits']:

		# initialise an entry in ips_obj for the ip, to store all info about it
		ips_obj[hit['ip']] = {}

		# throw in some initially useful info about the ip
		ips_obj[hit['ip']]['services'] = hit['services']
		ips_obj[hit['ip']]['location'] = hit['location']['country'] + " - " + hit['location']['city']
		ips_obj[hit['ip']]['asn'] = {'asnId': hit['autonomous_system']['asn'], 'name': hit['autonomous_system']['name']}
		
		# now we do a further API call to get more information about the ip not initially available
		res2 = requests.get(API_URL + "/v2/hosts/" + hit['ip'], auth=(censys_id, censys_secret)).json()['result']['services']
		
		# for each of the services running on this IP (will only be HTTP/HTTPS)
		for service in res2:

			# use the extended service name (HTTP/HTTPS) as the key for the entry to ips_obj['ip']
			ips_obj[hit['ip']][service['extended_service_name']] = {}

			# if its an HTTPS service, we can get the JARM signature and the domains relating to certificate
			if service['extended_service_name'] == "HTTPS": 
				ips_obj[hit['ip']][service['extended_service_name']]['domains'] = service['tls']['certificates']['leaf_data']['names']
				ips_obj[hit['ip']][service['extended_service_name']]['jarm'] = service['jarm']['fingerprint']
			
			# get all software censys knows is running 
			ips_obj[hit['ip']][service['extended_service_name']]['software'] = service['software']
			
	return(ips_obj)

#subdomains_obj = subdomains('')
#ips_obj = ips('')
