import os
import requests
import json

# Initialize API key from environment for security
apikey = os.environ.get('VT_API_KEY')
if not apikey:
    print("Warning: VT_API_KEY environment variable not set. VirusTotal checks will likely fail.")

# Get user input
url_input = input('Enter the URL to analyze: ').strip()

# Prepare API request
params = {'apikey': apikey, 'resource': url_input}
url = 'https://www.virustotal.com/vtapi/v2/url/report'

try:
    # Send GET request to VirusTotal API with timeout
    response = requests.get(url, params=params, timeout=10)
    response.raise_for_status()
    response_json = response.json()
except Exception as e:
    print("Error contacting VirusTotal:", e)
    response_json = {}

# Analyze response
if not response_json:
    print("No response from VirusTotal. Please try again later.")
elif response_json.get('response_code') == 0:
    print("The URL you are looking for does not exist. Please try again.")
elif response_json.get('positives', 0) == 0:
    print("The URL is not malicious.")
else:
    print("The URL is malicious!")
    
print("I hope to see you again :)") 

