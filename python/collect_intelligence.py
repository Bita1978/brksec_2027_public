import requests
import json
import datetime

#PART 1 
#this script is the first part of the use case for BRKSEC-2027 @ CLUS 2019
#---------------------------------------------------------------
# the goal of this script is to build a way to collect intelligence from Threat Grid centered on Parameter
# we will be using the classic example of Cryptomining and how we can properly look for the latest threats

#Section 1 decided where we are going to use as our intelligence and validating it so its clean and ready for part 2

debug = True
tg_key = "keykeykeykeykeykey"
tg_url = "https://panacea.threatgrid.com/api/v2/search/submissions"
headers = {"content-type" : "application/json"}
past_hour = (datetime.datetime.utcnow() - datetime.timedelta(hours=1, minutes=0)).replace(microsecond=0).isoformat()
parameters = {
				"api_key": tg_key,
				"after" : past_hour,
				"term" : "behavior",
				"q" : "cryptominer",
			}

session = requests.Session()

#need to iterate over all the pages
#get the output from TG
response = session.get(tg_url, headers=headers, params=parameters)
response_json = response.json()
sha_list = []
sample_list = []
for item in response_json["data"]["items"]:
	sha_list.append(item["item"]["sha256"])
	sample_list.append(item["item"]["sample"])
if debug:
	print("INFO: total of {} samples found!".format(len(sample_list)))

# need to get network data for each sample now

tg_url = "https://panacea.threatgrid.com/api/v2/samples/feeds/domains"
parameters = {
				"api_key": tg_key,
				"sample": ",".join(sample_list)
			}
response = session.get(tg_url, headers=headers, params=parameters)
response_json = response.json()
domains = []
for domain in response_json["data"]["items"]:
	domains.append(domain["domain"])

domain_list = list(set(domains))
if debug:
	print("INFO: total of {} domains found!".format(len(domain_list)))
#here we have our two sets of intelligence for the past hour with anything related to cryptomining

#we must curate the list and pull up any relationships as of interest so we move to umbrella 

investigate_token = "keykeykeykeykeykey-664c-4b6f-b79e-keykeykeykeykeykey"
co_occurence_url = "https://investigate.api.umbrella.com/recommendations/name/{}.json"
related_url = "https://investigate.api.umbrella.com/links/name/{}.json"
category_url = "https://investigate.api.umbrella.com/domains/categorization/"
headers = {	"Authorization" : "Bearer {}".format(investigate_token),
			"content-type" : "application/json"}

session_umbrella = requests.Session()

co_occuring_domains=[]
related_domains=[]
pruned_domains=[]

for domain in domain_list:
	response = session_umbrella.get(co_occurence_url.format(domain), headers=headers)
	if response.json()["found"] == True:
		for domains in response.json()["pfs2"]:
			co_occuring_domains.append(domains[0])
if debug:
	print("INFO: total of {} co-occuring domains found!".format(len(co_occuring_domains)))


for domain in domain_list:
	response = session_umbrella.get(related_url.format(domain), headers=headers)
	if response.json()["found"] == True:
		for domains in response.json()["tb1"]:
			related_domains.append(domains[0])
if debug:
	print("INFO: total of {} related domains found!".format(len(related_domains)))

domains = domain_list + co_occuring_domains + related_domains

#now that we have a full list prun this thing out so there is not noise we dont care about 
response = session_umbrella.post(category_url, headers=headers, json=domains)
domain_details = response.json()
for domain,status in domain_details.items():
	#check to see if the domain is of interest
	if status["status"] != 1 :
		pruned_domains.append(domain)

if debug:
	print("INFO: total of {} domains pruned!".format(len(domains)-len(pruned_domains)))

# now we have two curated lists of intelligence Its time to investigate these to discover exposure
if debug:
	print("INFO: Domain List: ", pruned_domains)
	print("INFO: SHA256 List: ", sha_list)

#write results out to a file to transfer to next section
file = open("sha_list.json","w")
file.write("[")
for sha in sha_list[:-1]:
	file.write("{\"value\":")
	file.write("\"{}\",".format(sha))
	file.write("\"type\":\"sha256\"")
	file.write("},")
file.write("{\"value\":")
file.write("\"{}\",".format(sha_list[-1]))
file.write("\"type\":\"sha256\"")
file.write("}")
file.write("]")
file.close
 

file = open("domain_list.json","w")
file.write("[")
for domain in pruned_domains[:-1]:
	file.write("{\"value\":")
	file.write("\"{}\",".format(domain))
	file.write("\"type\":\"domain\"")
	file.write("},")
file.write("{\"value\":")
file.write("\"{}\",".format(pruned_domains[-1]))
file.write("\"type\":\"domain\"")
file.write("}")
file.write("]")
file.close
