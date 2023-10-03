import urllib
import requests
import json
import ipaddress
import re

# abuseipdb api
url = 'https://api.abuseipdb.com/api/v2/check'
API_KEY = '359eed821486c5be8ce28d06a929938917e7cf150e4866fee1f19929c9a70d7465f21baf7c043a05'

def check_ip(IP, days):
    if ipaddress.ip_address(IP).is_private is False:
        headers = {
            'Key': API_KEY,
            'Accept': 'application/json',
        }

        params = {
            'maxAgeInDays': days,
            'ipAddress': IP,
            'verbose': ''
        }

        r = requests.get('https://api.abuseipdb.com/api/v2/check',
                         headers=headers, params=params)
        response = r.json()
        if 'errors' in response:
            print(f"Error: {response['errors'][0]['detail']}")
            exit(1)
        else:
            if response['data']['totalReports'] > 0:
                    for report in response['data']['reports']:
                        tmp_catergory = []
                        category = report['categories']
                        for cat in category:
                            tmp_catergory.append(get_cat(cat))
                        report['categories'] = tmp_catergory
            return response['data']
    else:
        return (f"{IP} is private. No Resuls")


def get_cat(x):
    return {
        0: 'BLANK',
        3: 'Fraud_Orders',
        4: 'DDoS_Attack',
        5: 'FTP_Brute-Force',
        6: 'Ping of Death',
        7: 'Phishing',
        8: 'Fraud VoIP',
        9: 'Open_Proxy',
        10: 'Web_Spam',
        11: 'Email_Spam',
        12: 'Blog_Spam',
        13: 'VPN IP',
        14: 'Port_Scan',
        15: 'Hacking',
        16: 'SQL Injection',
        17: 'Spoofing',
        18: 'Brute_Force',
        19: 'Bad_Web_Bot',
        20: 'Exploited_Host',
        21: 'Web_App_Attack',
        22: 'SSH',
        23: 'IoT_Targeted',
    }.get(
        x,
        'UNKNOWN CATEGORY!')


def check_domain(DOMAIN):
        encoded_url = urllib.parse.quote(DOMAIN, safe='')
        api_url = "https://ipqualityscore.com/api/json/url/hC1eDQ7GJyfDG1PvvvHGsgCGWbBbkpwr/"
        data = requests.get(api_url + encoded_url)
        print("Domainss Result from IP Quality Score\n")
        print(json.dumps(data.json(), indent=4))


while(True):
    choice = int(input("1: Check IP reputation\n2: Check domain reputation:\n3: to exit!\n"))

    if choice==1:
        IP = input("Please enter IP to check if abused by hackers: ")
        json_logs = json.dumps(check_ip(IP,30),indent=4)
        print("IPs Result from AbuseIpDb\n")
        print(json_logs)
    elif choice==2:
        domain = input("Please enter Domain Name to check if abused by hackers: ")
        check_domain(domain)
    elif choice==3:
        exit(1)
    else:
         print("please chose one of the options!")
