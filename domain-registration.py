import requests

# will be using the rdap api to find out as much domain registration info as poss
def rdap(domain, tld):

	# initialize rdap_object which will store all info related to domain registration
	rdap_object = {"registrar": {}, "registrant": {}}

	# initial api call to get registrar information using rdap api
	res2 = requests.get("https://rdap.verisign.com/" + tld + "/v1/domain/" + domain)
	
	# store registration events in initial_registration
	initial_registration = res2.json()['events']

	# for each of the registration events
	for i in initial_registration:

		if i['eventAction'] == 'registration':
			reg_date = i['eventDate']
			rdap_object['registrationDate'] = reg_date

		elif i['eventAction'] == 'expiration':
			exp_date = i['eventDate']
			rdap_object['expirationDate'] = exp_date

		elif i['eventAction'] == 'last changed':
			upd_date = i['eventDate']
			rdap_object['updateDate'] = upd_date

	# iterate through entities obtained from res2 request
	for entity in res2.json()['entities']:
		
		# find information about the registrar
		if 'registrar' in entity['roles']:

			# api returns a strange double array, iterate through these
			for x in entity['vcardArray']:
				for y in x:

					# 'fn' relates to the area containing registrar details (i.e. name)
					if 'fn' in y:
						registrar_name = y[-1]
						rdap_object['registrar']['registrarName'] = registrar_name
	
	return rdap_object

# we're using a domain from the most recent NCSC malicious domain list
rdap('4MATIONDRILLING.COM', 'com')
