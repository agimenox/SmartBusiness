import requests
import os

API_KEY = os.environ.get('VT_KEY')


def domain_report(domain):
    url = 'https://www.virustotal.com/api/v3/domains/'
    url_with_domain = url + domain
    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url_with_domain, headers=headers)
    response_in_json = response.json()
    return response_in_json

def ip_report(ip):

    url = 'https://www.virustotal.com/api/v3/ip_addresses/'
    url_with_ip = url + ip

    headers = {
        "x-apikey": API_KEY
    }
    response = requests.get(url_with_ip, headers=headers)
    response_in_json = response.json()
    return response_in_json

def upload_file(file):

    # Prepare the file for uploading to the VirusTotal API
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': API_KEY
    }
    files = {'file': file}

    # Upload the file to VirusTotal
    response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        data = response.json()
        file_id = data['data']['id']
        final_output_file = os.path.join(os.getcwd(), 'panel_app', 'static', 'file_scan_ids.txt')
        with open(final_output_file, 'w') as f:
            f.write(f'{file_id}\n')
        return file_id
        # Perform further operations with the response data, such as retrieving examination results
        # based on the 'file_id'
    else:
        return False
    
def consult_file_report(file_id):
    # Prepare the URL for getting the file report
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'

    # Set the VirusTotal API key in the headers
    headers = {
        'x-apikey': API_KEY
    }

    # Send GET request to retrieve the file report
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data
        # Perform further operations with the file report data
    else:
        return False






