import time
import requests
from requests.exceptions import RequestException

url = 'http://127.0.0.1:5000/api/transactions'
headers = {'Accept': 'application/json'}

attempts = 20
wait = 0.5

for i in range(attempts):
    try:
        r = requests.get(url, headers=headers, timeout=10)
        with open('tmp_tx_response.txt', 'w', encoding='utf-8') as f:
            f.write(str(r.status_code) + '\n')
            f.write(str(r.headers.get('Content-Type')) + '\n')
            f.write(r.text)
        print('WROTE tmp_tx_response.txt')
        break
    except RequestException as e:
        if i == attempts - 1:
            with open('tmp_tx_response.txt', 'w', encoding='utf-8') as f:
                f.write('ERROR\n')
                f.write(str(e))
            print('WROTE tmp_tx_response.txt (error)')
        else:
            time.sleep(wait)
