import asyncore 
import socket 
import struct
import time 
import hashlib
import base64

"""
WebSocket Version 13, update security hand shake.
"""
class WebSocketConnection(asyncore.dispatcher_with_send):

	def __init__(self, conn, server):
		asyncore.dispatcher_with_send.__init__(self, conn)

		self.server = server
		self.server.sessions.append(self)
		self.readystate = "connecting"
		self.buffer = ""

	def handle_read(self):
		data = self.recv(1024)
		self.buffer = data

		if self.readystate == "connecting":
			print "readystate is connecting"
			self.parse_connecting()
		elif self.readystate == "open":
			self.parse_frametype()

	def handle_close(self):
		if self.server.sessions.count(self) > 0:
			self.server.sessions.remove(self)
		self.close()

	def parse_connecting(self):
		header_end = self.buffer.find("\r\n\r\n")
		if header_end == -1:
			return
		else:
			header = self.buffer[:header_end]
			# remove header and four bytes of line endings from buffer
			self.buffer = self.buffer[header_end+4:]
			header_lines = header.split("\r\n")
			headers = {}

		# validate HTTP request and construct location
		method, path, protocol = header_lines[0].split(" ")
		if method != "GET" or protocol != "HTTP/1.1" or path[0] != "/":
			self.terminate()
			return
        
		# parse headers
		for line in header_lines[1:]:
			key, value = line.split(": ")
			headers[key] = value
        
		headers["Location"] = "ws://" + headers["Host"] + path

		self.readystate = "open"
		self.handler = self.server.handlers.get(path, None)(self)

		if "Sec-WebSocket-Key" in headers.keys():
			self.send_server_handshake_13(headers)

	def terminate(self):
		self.ready_state = "closed"
		self.close()

	def send_server_handshake_13(self, headers):
		"""
		Send the WebSocket Protocol v.13 handshake response
		"""

		key = headers["Sec-WebSocket-Key"]
  
		response_token = self.calculate_key_13(key)

		# write out response headers
		self.send_bytes("HTTP/1.1 101 Web Socket Protocol Handshake\r\n")
		self.send_bytes("Upgrade: websocket\r\n")
		self.send_bytes("Connection: Upgrade\r\n")
		self.send_bytes("Sec-WebSocket-Origin: %s\r\n" % headers["Origin"])
		self.send_bytes("Sec-WebSocket-Location: %s\r\n" % headers["Location"])
		# write out encoded response token
		self.send_bytes("Sec-WebSocket-Accept: %s\r\n" % response_token)

		if "Sec-WebSocket-Protocol" in headers:
			protocol = headers["Sec-WebSocket-Protocol"]
			self.send_bytes("Sec-WebSocket-Protocol: %s\r\n" % protocol)
        
		self.send_bytes("\r\n")

	def calculate_key_13(self, key):
		# parse security key for version 10
		newKey = key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
		newKey = hashlib.sha1(newKey)
		newKey = newKey.digest()
		newKey = base64.b64encode(newKey)
		return newKey

	def parse_frametype(self):
		if len(self.buffer) == 0:
			return
		code_length = ord(self.buffer[1])&127
		masks = ''
		data = ''
		i = 0
		frame = ''
		if code_length == 126:
			masks = self.buffer[4:8]
			data = self.buffer[8:]
		elif code_length == 127:
			masks = self.buffer[10:14]
			data = self.buffer[14:]
		else:
			masks = self.buffer[2:6]
			data = self.buffer[6:]
		for d in data:
			frame += chr(ord(d) ^ ord(masks[i%4]))
			i += 1	
		self.handler.dispatch(frame)		

	def send(self, s):
		if self.readystate == "open":
			token = '\x81'	
			data_length = len(s)
			if data_length < 126:  
				token += struct.pack("B", data_length)  
			elif data_length <= 0xFFFF:  
				token += struct.pack("!BH", 126, data_length)  
			else:  
				token += struct.pack("!BQ", 127, data_length) 
			send_str = '%s%s' % (token,s) 
			
			try:
				self.send_bytes(send_str)
			except:
				print "exception occurs when connection send"

	def send_bytes(self, bytes):
		try:
			asyncore.dispatcher_with_send.send(self, bytes)
			# clean the buffer
			self.buffer = ""
		except:
			print "exception occurs when dispatcher send"

class EchoHandler(object):
	"""
	The EchoHandler repeats each incoming string to the same Web Socket.
	"""
        
	def __init__(self, conn):
		self.conn = conn

	def dispatch(self, data):
		dispatch_str = "echo: " + data
		self.conn.send(dispatch_str)

class WebSocketServer(asyncore.dispatcher):
	def __init__(self, port=80, handlers=None):
		asyncore.dispatcher.__init__(self)
		self.handlers = handlers
		self.sessions = []
		self.port = port
		self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		self.set_reuse_addr()
		self.bind(("", port))
		self.listen(5)
		
	def handle_accept(self):
		print "accepting"
		conn, addr = self.accept()
		session = WebSocketConnection(conn, self)
		
if __name__ == "__main__":
	print "Starting WebSocket Server"
	WebSocketServer(port=8080, handlers={"/echo": EchoHandler})
	asyncore.loop()
