import argparse
import socket
import requests
import ipaddress
import json

def print_ASN_country_descr(ip):

	if (ip == "timeout"):
		return

	if not(ipaddress.ip_address(ip).is_global):
		return

	url = "https://rest.db.ripe.net/search.json?query-string=" + ip
	fallback_url = "http://whois.arin.net/rest/ip/" + ip + '.json'
	response = requests.get(url)
	json_data = response.json()

	origin = "N/A"
	country = "N/A"
	descr = "N/A"

	try:		# in case the format differs
		for data in json_data["objects"]["object"][0]["attributes"]["attribute"]:
			if (data['name'] == "country"):
				country = data["value"]
			if (data['name'] == "descr"):
				descr = data["value"]
	except Exception:
		pass

	try:
		for i in range(len(json_data["objects"]["object"])):
			for data in json_data["objects"]["object"][i]["attributes"]["attribute"]:
				if (data['name'] == "country"):
					country = data['value']
				if (data['name'] == "descr"):
					descr = data['value']
			for data in json_data["objects"]["object"][i]["primary-key"]["attribute"]:
				if (data['name'] == "origin"):
					origin = data['value']
	except Exception:
		pass

	if ("not managed by the RIPE NCC" in descr):
		fallback_response = requests.get(fallback_url)
		fallback_json_data = fallback_response.json()
		try:
			origin = fallback_json_data["net"]["originASes"]["originAS"]["$:"]
		except Exception:
			pass

		try:
			descr = fallback_json_data["net"]["orgRef"]["@name"]
		except Exception:
			pass

		try:
			if (fallback_json_data["net"]["@copyrightNotice"] == "Copyright 1997-2020, American Registry for Internet Numbers, Ltd."):
				country = "US"
		except Exception:
			pass

	print(origin + "\t" + country + "\t" + descr, end="")

parser = argparse.ArgumentParser()
parser.add_argument("destination", type=str)
args = parser.parse_args()
destination_ip = socket.gethostbyname(args.destination)

current_ip = ""
print("TTL" + "\t" + "ip" + "\t" + "\t" + "ASN" + "\t" + "country" + "\t" + "org")
for ttl in range(1, 64):
	icmp = socket.getprotobyname('icmp')
	_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
	_socket.settimeout(3)
	_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
	query = bytearray.fromhex('0800 B5BC 4242 0001')
	try:
		_socket.sendto(query, (destination_ip, 43))
		current_ip = _socket.recvfrom(1024)[1][0]
		_socket.close()
	except socket.timeout:
		_socket.close()
		current_ip = "timeout"

	print(str(ttl) + "\t" + current_ip + "\t", end="")
	print_ASN_country_descr(current_ip)
	print("")
	if (destination_ip == current_ip):
		break