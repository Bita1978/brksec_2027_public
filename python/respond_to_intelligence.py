import requests
import json
import datetime

#PART 3
#this script is the third and final part of the use case for BRKSEC-2027 @ CLUS 2019
#---------------------------------------------------------------
# the goal of this script is to take intelligence gathered and quantified and take intial remedation steps

#first part will be add items to take endpoints that have been targets from the previous step and moving them to new group

#get the amp group GUID that we want to move computers into
debug = True
amp_client_id = "keykeykeykeykeykey"
amp_api_key = "keykeykeykeykeykey-0000-4b57-a4fc-keykeykeykeykeykey"

amp_group_url = 'https://{}:{}@api.amp.cisco.com/v1/groups'.format(amp_client_id, amp_api_key)

headers = {
	"accept" : "application/json",
	"content-type" : "application/json"
}

groups = requests.get(amp_group_url, headers=headers)
for group in groups.json()['data']:
	if group['name'] == 'Demo-LAB':
		#found group set group ID
		group_guid = group['guid']
		group_name = group['name']
		if debug:
			print("INFO: Found group: {} with id {}".format(group['name'],group['guid']))
		break
	else:
		print("INFO: Group not found!!")
		group_guid = "none"
if debug:
	print("INFO: Final group id - {}".format(group_guid))


targets = open('targets.json','r')
endpoint_ids = []
for target in targets:
	#for each target we will move the endpoint to a new group so that it is ready to work on
	target_json = json.loads(target[1:-2])
	if target_json['type'] != 'endpoint':
		print("ERROR: NO ENDPOINT OBSERVABLES FOUND EXITING...")
		break
	if debug:
		print(target_json)

	#check to see if group is there or we will break everything
	if group_guid == "none":
		print("ERROR: NO GROUP FOUND EXITING...")
		break
	else:
		#pull out the IDs for all impacted endpoints
		for value in target_json['observables']:
			if value['type'] == 'amp_computer_guid':
				endpoint_ids.append(value['value'])
endpoint_ids = list(set(endpoint_ids))
group_guid_json = {'group_guid': group_guid}
if debug:
	print(endpoint_ids)
if not endpoint_ids:
	print("ERROR: NO ENDPOINTS TO MOVE EXITING...")
else:
	if debug:
		print ("INFO: moving {} endpoints to the group {}".format(len(endpoint_ids),group_name))
	for endpoint in endpoint_ids:
		url = "https://{}:{}@api.amp.cisco.com/v1/computers/{}".format(amp_client_id,amp_api_key,endpoint)
		response = requests.patch(url,headers=headers, json=group_guid_json)
		if debug:
			print(response.json())

