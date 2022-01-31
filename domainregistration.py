import requests

# will be using the rdap api to find out as much domain registration info as poss
def rdap(domain, tld):

	# initialize rdap_object which will store all info related to domain registration
	rdap_object = {"registrar": {}, "registrant": {"registrantName": "", "organisationName": "", "address": "", "telephone": "", "email": ""}}

	# initial api call to get registrar information using rdap api
	res2 = requests.get("https://rdap.verisign.com/" + tld + "/v1/domain/" + domain)
	
	# store registration events in initial_registration
	initial_registration = res2.json()['events']

	# for each of the registration 
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
	
	# we now need to find the link to the registrant's info, so iterate through links
	for link in res2.json()['links']:
		# here rel = related for the link relating to the registrant
		if link['rel'] == 'related':
			print(link['href'])
			registrant_link = link['href']

	# we're now going to GET from the registrant's link, another RDAP API call
	registrant_res = requests.get(registrant_link)
	
	# iterate through the entities to find registrant's details, and store
	for i in registrant_res.json()['entities']:
		if 'registrant' in i['roles']:

			# weird nested array thing again
			for z in i['vcardArray']:
				for y in z:

					if 'fn' in y:
						customer_name = y[-1]
						rdap_object['registrant']['registrantName'] = customer_name
					if 'org' in y:
						org_name = y[-1]
						rdap_object['registrant']['organisationName'] = org_name
					if 'adr' in y:
						address_array = y[-1]
						address = ""
						for string in address_array:
							if string != "":
								address += str(string) + " "
						rdap_object['registrant']['address'] = address
					if 'tel' in y:
						telephone = y[-1]
						rdap_object['registrant']['telephone'] = telephone
					if 'email' in y:
						email = y[-1]	
						rdap_object['registrant']['email'] = email


	return rdap_object

# we're using a domain from the most recent NCSC malicious domain list
#print(rdap('4MATIONDRILLING.COM', 'com'))
