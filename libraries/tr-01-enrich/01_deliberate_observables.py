import requests
import json

access_token = 'eyJhbGciO....bPito5n5Q' # Truncated example

url = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/deliberate/observables'

headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}

deliberate_payload = [{'type': 'domain', 'value': 'cisco.com'}]

deliberate_payload = json.dumps(deliberate_payload)

response = requests.post(url, headers=headers, data=deliberate_payload)

print(response.json())