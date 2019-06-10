import requests
import json
import datetime

#PART 2
#this script is the second of the use case for BRKSEC-2027 @ CLUS 2019
#---------------------------------------------------------------
# the goal of this script is to take an intelligence source and investigate it in your environment

#Section 2 we will create a list of actions needed for the next step
debug = True
client_id = 'client-keykeykeykeykeykey-41ba-439f-9a39-keykeykeykeykeykey'
client_password = '-ci8-keykeykeykeykeykey-keykeykeykeykeykey-TUQ'

url = 'https://visibility.amp.cisco.com/iroh/oauth2/token'
headers = {'Content-Type':'application/x-www-form-urlencoded', 
			'Accept':'application/json'}
payload = {'grant_type':'client_credentials'}
response = requests.post(url, headers=headers, auth=(client_id, client_password), data=payload)

access_token = response.json()['access_token']

url = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/observables'
headers = {'Authorization':'Bearer {}'.format(access_token), 
			'Content-Type':'application/json', 
			'Accept':'application/json'}



#now we can take the intelligence in from last 

with open('domain_list_poc.json') as file:
    domains = json.load(file)
with open('sha_list_poc.json') as file:
    shas = json.load(file)
target_file = open("targets.json","w")

response = requests.post(url, headers=headers, json=shas[0:1])
sha_investigate = response.json()

#to speed up processing we are only going to make a request with the first domain
response = requests.post(url, headers=headers, json=domains[0:1])
domain_investigate = response.json()

#once we get the results we need to parse through and get any relevant sightings so we can take some actions
for module in sha_investigate['data']:
	if 'sightings' in module['data']:
		if debug:
			print("INFO: {} sightings found in {}".format(module['data']['sightings']['count'],module['module']))
		#now that we have sightings we need to figure out what to do with them for use in remediation/containment
		#gotta check to see if its actual targets and not just intel
		for sighting in module['data']['sightings']['docs']:
			if 'targets' in sighting:
				if debug:
					print("INFO: {}".format(sighting['description']))
					#write targets out to a target file
				target_file.write(str(json.dumps(sighting['targets'])))
				target_file.write("\n")
			else:
				if debug:
					print("INFO: No targets found in {}".format(module['module']))
	else:
		if debug:
			print("INFO: No sightings in {}".format(module['module']))

for module in domain_investigate['data']:
	if 'sightings' in module['data']:
		if debug:
			print("INFO: {} sightings found in {}".format(module['data']['sightings']['count'], module['module']))
		#now that we have sightings we need to figure out what to do with them for use in remediation/containment
		#gotta check to see if its actual targets and not just intel
		for sighting in module['data']['sightings']['docs']:
			if 'targets' in sighting:
				#now that we have the targets we gotta give as much info as we can to the admin to spawn work here
				if debug:
					print("INFO: {}".format(sighting['description']))
					#write targets out to a target file
				target_file.write(str(json.dumps(sighting['targets'])))
				target_file.write("\n")
			else:
				if debug:
					print("INFO: No targets found in {}".format(module['module']))
	else:
		if debug:
			print("INFO: No sightings in {}".format(module['module']))
target_file.close()