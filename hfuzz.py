#!/Users/apple/env/bin/python

import requests
import os
import sys
import argparse
import json
import random
import time
import threading



def banner():
	print("""        _  _
       (.)(.)
   ,-.(.____.),-.  
  ( \ \ '--' / / )
   \ \ / ,. \ / /
    ) '| || |' ( mrf
OoO'- OoO''OoO -'OoO



""")
	pass


def usage():
	print("Usage : hfuzz.py -u <url> -f <headers_files>")
	sys.exit(-1)


def make_payload(header_filename, header_name=None,header_value=None):
	f = open(header_filename)
	data = json.load(f)
	keys_array = []
	value_array = []
	headers = {}
		
	for keys, values in data['http_headers'][0].items():
		# keys_array.append(keys)
		# value_array.append(values)
		headers[keys] = values


	if header_name and header_value:
		headers[header_name] = header_value
	
	return headers


def append_urls(url, path):
	urls = []

	with open(path, "rb") as f:
		for filepath in f.readlines():
			filepath = filepath.decode().strip()
			if filepath[0] == "/" and url[-1] !='/':
				urls.append(url + filepath)
			elif filepath[0] != '/' and url[-1] == '/':
				urls.append(url + filepath)
			elif filepath[0] != '/' and url[-1] != '/':
				filepath = "/" + filepath
				urls.append(url + filepath)
			elif filepath[0] == '/' and url[-1] == '/':
				url = url[:-1]
				urls.append(url + filepath)

	return urls


def prepare_request(urls, headers):
	data = {'key': 'value'}
	udata = {'key': 'updated_value'}
	for url in urls:
		res_get = requests.get(url, headers)
		res_post = requests.post(url, data=data)
		res_put = requests.put(url, data=udata)
		res_delete = requests.delete(url)
		res_patch = requests.patch(url, data=data)



	with open("output.txt", "wb") as f:
		for ka, dr in headers.items():
			if dr in res_get.text:
				f.write("GET--HEADERS")
				f.write("suspicious header name : {} value : {}".format(str(ka), str(dr)))
				f.write("  <<<<END-GET>>>>  ")
			elif dr in res_post.text:
				f.write("POST--HEADERS")
				f.write("suspicious header name : {} value : {}".format(str(ka), str(dr)))
				f.write("  <<<<END-POST>>>>  ")
			elif dr in res_put.text:
		 		f.write("PUT--HEADERS")
		 		f.write("suspicious header name : {} value : {}".format(str(ka), str(dr)))
		 		f.write("  <<<<END-PUT>>>>  ")
			elif dr in res_delete:
				f.write("DELETE--HEADERS")
				f.write("suspicious header name : {} value : {}".format(str(ka), str(dr)))
				f.write("  <<<<END-DELETE>>>>  ")
			elif dr in res_patch:
				f.write("PATCH--HEADERS")
				f.write("suspicious header name : {} value : {}".format(str(ka), str(dr)))
				f.write("  <<<<END-PATCH>>>>  ")
		f.write(b"-=========END========-")

			

def main():
	parser = argparse.ArgumentParser(prog="H-FUZZER", description="Example command line interface", epilog="http header fuzzer")

	parser.add_argument("-u", "--url", help="target url", required=True)
	parser.add_argument("-p", "--pathfile", help="give me url path file", required=True)
	parser.add_argument("-f", "--filename", help="http header file json format", required=True)
	parser.add_argument("-v", "--header_value", help="specify custome header value", required=True)
	parser.add_argument('-n', "--header_name", help="specify header name", required=True)
	parser.add_argument("-t", "--thread", help="specify number of thread")

	args = parser.parse_args()

	if len(sys.argv) < 4:
		usage()
	banner()

	print("[*] Starting hfuzzer.....")
	time.sleep(2)
	print("[*] Preparing urls....")

	time.sleep(1)
	url_path = []
	if args.pathfile:
		all_urls = append_urls(args.url, args.pathfile)

	# now prepare headers.

	print("[*] Preparing custome and default payload headers....")
	time.sleep(1)
	if args.header_name and args.header_value:
		payload_headers = make_payload(args.filename, args.header_name, args.header_value)

	print("[*] Starting fuzzing....")

	time.sleep(1)
	threads = []
	if args.thread:
		for i in range(int(args.thread)):
			t = threading.Thread(target=prepare_request, args=(all_urls, payload_headers))
			threads.append(t)

		for thread in threads:
			thread.start()

	else:
		prepare_request(all_urls, payload_headers)




	print("[*] Fuzzing complere!! Thank you.")


if __name__ == "__main__":
	main()


