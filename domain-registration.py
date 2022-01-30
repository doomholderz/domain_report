import requests

def rdap(domain, tld):
	# Make two API calls using RDAP API to get domain registration details
	# res obtains domain registrant
	#res = requests.get("https://domainsrdap.googleapis.com/v1/domain/4MATIONDRILLING.COM")
	# NEED TLD FOR THIS TO GO BETWEEN .COM/ AND /V1
	res2 = requests.get("https://rdap.verisign.com/" + tld + "/v1/domain/" + domain)
	
	initial_registration = res2.json()['events']
	#registration = res.json()
	#print(registration)
	
	for i in initial_registration:
		if i['eventAction'] == 'registration':
			reg_date = i['eventDate']
			print(reg_date)
		elif i['eventAction'] == 'expiration':
			exp_date = i['eventDate']
			print(exp_date)
		elif i['eventAction'] == 'last changed':
			upd_date = i['eventDate']
			print(upd_date)

	for i in res2.json()['entities']:
		
		if 'registrar' in i['roles']:
			for z in i['vcardArray']:
				for y in z:
					if 'fn' in y:
						registrar_name = y[-1]
						print(registrar_name)
	
	
rdap('4MATIONDRILLING.COM', 'com')