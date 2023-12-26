'''
@author: Lê Ngọc Hoa - 20200234 - IT2-02 K65
'''

# xử lý input cho tool
import argparse
# xử lý tách các thành phần trong URL, package request
from urllib.parse import urlparse, parse_qs
# dùng cho gửi request tới server
import requests
import time
from datetime import datetime

# payload list default
PAYLOADS_PATH = './payloads.txt'
LOG = 0

# Create the parser
parser = argparse.ArgumentParser()

parser.add_argument('-url', help = 'Target URL (e.g. "http://www.site.com/vuln.php?id=1")', type = str, required = False)
parser.add_argument('-packet', help = 'Load HTTP request from a file path (e.g. "./package.txt")', type = str, required = False)
parser.add_argument('-payloadlist', help = 'Load list payloads from a file path (e.g. "./payloads.txt")', type = str, required = False)
parser.add_argument('-log', help = 'Show the log', action="store_true", required = False)
parser.add_argument('-cookies', help = 'Cookies testing', action="store_true", required = False)

args = parser.parse_args()

def get_processor(url):
    parsed_url = urlparse(url)
    query_parameters_ = parse_qs(parsed_url.query)
    query_parameters = {}
    for key, value in query_parameters_.items():
        query_parameters[key] = value[0]
    scheme = parsed_url.scheme
    netloc = parsed_url.netloc
    path = parsed_url.path
    return netloc, path, query_parameters

def post_processor(filename):
    with open(filename, 'r') as f:
        post_request = f.readlines()
    # print(post_request)
    body = {}
    if len(post_request[-1]) > 1:
        body_list = post_request[-1].split('&')
        for item in body_list:
            key, value = item.split('=')
            body[key] = value
    path, netloc, content_type, cookie_string = '', '', '', ''
    for line in post_request:
        if line.startswith('POST'):
            path = line.split(' ')[1]
        if line.startswith('Host'):
            netloc = line.split(' ')[1][:-1]
        if line.startswith('Content-Type'):
            content_type = line.split(' ')[1][:-2]
        if line.startswith('Cookie'):
            cookie_string = line[8:].strip()
    # xử lý cookie --> chuyển sang dict
    if len(cookie_string) > 0:
        cookies_list = cookie_string.split('; ')
        cookies = {cookie.split('=')[0]: cookie.split('=')[1] for cookie in cookies_list}
    else:
        cookies = {}
    return netloc, path, cookies, content_type, body

# gửi request đối với get
def get_request_send(netloc, path, query_parameters):
    # xây dựng lại URL
    url = 'https://%s%s?' % (netloc, path)
    params_part = ''
    for key, value in query_parameters.items():
        params_part += '&' + key + '=' + value
    url += params_part[1:]
    # print(url)
    r = requests.get(url = url)
    # print(r.text.strip())
    return r, url

# gửi request đối với post
def post_request_send(netloc, path, cookies, content_type, body):
    url = 'https://%s%s' % (netloc, path)
    r = requests.post(url = url, cookies = cookies, data = body, allow_redirects = False)
    return r, url

# gửi request đối với get và cookie testing
def get_request_send_cookies(netloc, path, cookies):
    # xây dựng lại URL
    url = 'https://%s%s?' % (netloc, path)
    # print(url)
    r = requests.get(url = url, cookies = cookies)
    # print(r.text.strip())
    return r, url

# sleep detect GET
def process_payload_sleep_get(netloc, path, query_parameters):
    with open(PAYLOADS_PATH, 'r') as f:
        payloads = f.readlines()
    for payload in payloads:
        payload = payload.strip()
        for key, value in query_parameters.items():
            query_parameters_payload = query_parameters.copy()
            query_parameters_payload[key] = value + payload
            print(query_parameters_payload)
            start_time = time.time()
            r, url_test = get_request_send(netloc, path, query_parameters_payload)
            elapsed_time = time.time() - start_time
            ### 
            if LOG == 1:
                current_time = datetime.now().time()
                # print(current_time)
                formatted_time = current_time.strftime("%H:%M:%S")
                print('[%s] Payload testing: %s' % (formatted_time, payload))
            # print('Payload: %s' % payload)
            if elapsed_time >= 5:
                # Recheck
                recheck_payload = payload.replace("5", "10")
                query_parameters_payload[key] = value + recheck_payload
                if LOG == 1:
                    print("[!] Recheck payload: %s" % recheck_payload)
                recheck_start_time = time.time()
                r, url_test = get_request_send(netloc, path, query_parameters_payload)
                recheck_elapsed_time = time.time() - recheck_start_time
                if recheck_elapsed_time >= 10:
                    print('[+] SQL injection vulnerabilities detected')
                    print('[+] URL: %s' % url_test)
                    print('[+] Payload: %s' % payload)
                    return

# sleep detect POST - packet
def process_payload_sleep_post(netloc, path, cookies, content_type, body):
    with open(PAYLOADS_PATH, 'r') as f:
        payloads = f.readlines()
    for payload in payloads:
        payload = payload.strip()
        # đối với data truyền qua POST cần loại bỏ ký tự + và %20
        payload = payload.replace('+', ' ')
        payload = payload.replace('%20', ' ')
        if LOG == 1:
            current_time = datetime.now().time()
            formatted_time = current_time.strftime("%H:%M:%S")
            print('[%s] Payload testing: %s' % (formatted_time, payload))
        for key, value in body.items():
            body_payload = body.copy()
            body_payload[key] = value + payload
            # print(body_payload)
            start_time = time.time()
            r, url_test = post_request_send(netloc, path, cookies, content_type, body_payload)
            elapsed_time = time.time() - start_time
            # print(elapsed_time)
            if elapsed_time >= 5:
                # Recheck
                recheck_payload = payload.replace("5", "10")
                body_payload[key] = value + recheck_payload
                if LOG == 1:
                    print("[!] Recheck payload: %s" % recheck_payload)
                recheck_start_time = time.time()
                r, url_test = post_request_send(netloc, path, cookies, content_type, body_payload)
                recheck_elapsed_time = time.time() - recheck_start_time
                if recheck_elapsed_time >= 10:
                    print('[+] SQL injection vulnerabilities detected')
                    print('[+] URL: %s' % url_test)
                    print('[+] Payload: %s' % body_payload)
                    return
        # cookies testing
        if args.cookies:
            for key, value in cookies.items():
                cookies_payload = cookies.copy()
                cookies_payload[key] = value + payload
                # print(cookies_payload)
                start_time = time.time()
                r, url_test = get_request_send_cookies(netloc, path, cookies_payload)
                elapsed_time = time.time() - start_time
                # print(elapsed_time)
                if elapsed_time >= 5:
                    # Recheck
                    recheck_payload = payload.replace("5", "10")
                    cookies_payload[key] = value + recheck_payload
                    if LOG == 1:
                        print("[!] Recheck payload: %s" % recheck_payload)
                    recheck_start_time = time.time()
                    r, url_test = get_request_send_cookies(netloc, path, cookies_payload)
                    recheck_elapsed_time = time.time() - recheck_start_time
                    if recheck_elapsed_time >= 10:
                        print('[+] SQL injection vulnerabilities detected')
                        print('[+] URL: %s' % url_test)
                        print('[+] Payload: %s' % cookies_payload)
                        return

# nếu có path payload list
if args.payloadlist:
    PAYLOADS_PATH = args.payloadlist

if args.log:
    LOG = 1

# xử lý input là URL
if args.url:
    url = args.url
    netloc, path, query_parameters = get_processor(url)
    # print(query_parameters)
    # get_request_send(netloc, path, query_parameters)
    process_payload_sleep_get(netloc, path, query_parameters)
# xử lý input là package request (thường dùng cho POST request)
elif args.packet:
    pk = args.packet
    netloc, path, cookies, content_type, body = post_processor(pk)
    # post_request_send(netloc, path, cookies, content_type, body)
    process_payload_sleep_post(netloc, path, cookies, content_type, body)