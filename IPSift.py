#!/usr/bin/python
# Created by @sw4mp_f0x
# https://github.com/Sw4mpf0x/ 
#
# Parse a list of line delimited IP addresses or gnmap file 
# for false positive /24 subnets based on the number of live hosts found
# For example, the following will output all addresses in /24 subnets 
# where less that 250 hosts were found:
# 
# python IPSift.py -g scan.gnmap -o output.txt -c 250
#
# The assumption here is that /24 ranges with more than 250 hosts showing as live
# are false positives.
#
#
#

import re
from os.path import isfile
from optparse import OptionParser
	
def gnmap_parse(path):
	if isfile(path):
		addresses = []
		print "Gnmap file found, parsing..."
		with open(path) as file:
			for line in file:
				if "Up" in line:
					addresses.append('%s\n' % (line.split()[1]))
		return addresses
	else:
		parser.error("The gnmap file does not exists at the provided path")

def txt_parse(path):
	if isfile(path):
		addresses = []
		print "Txt file found, parsing..."
		with open(path) as file:
			for address in file:
				addresses.append(address)
		return addresses	
	else:
		parser.error("The txt file does not exists at the provided path")

def create_output_file(path, validaddresses, count):
	final_address_count = 0
	finaloutput = open(path, "w")
	for address_range in validaddresses:
		for address in address_range:
			finaloutput.write(address)
			final_address_count += 1
	finaloutput.close()
	print ""
	print "Valid ranges and addresses found to have less than " + count + " live hosts:"
	print "Valid ranges: " + str(len(validaddresses))
	print "Valid addresses: " + str(final_address_count)
	print "Output file " + path + " created"
	print ""
	
def main():
	# Argument parsing
	usage = "usage: %prog --gnmap gnmap_file_path --output output_file_path"
	global parser
	parser = OptionParser(usage=usage)
	parser.add_option('-g', '--gnmap', action="store", help='GNmap file to parse', dest='gnmap_path')
	parser.add_option('-o', '--output', action="store", help='Output file name', dest='output_path')
	parser.add_option('-f', '--falsepos', action="store", help='False Positive Output file name', dest='false_output_path')
	parser.add_option('-t', '--txt', action="store", help="Txt file to parse", dest='txt_path')
	parser.add_option('-c', '--count', action="store", help="Marked /24 as false positive if number of hosts in /24 is >= this number", dest='count', default='255')

	(options, args) = parser.parse_args()
	
	# Checking for required arguments
	if not options.gnmap_path and not options.txt_path or not options.output_path:
		parser.error("A file to parse (gnmap or txt) and output file name must be specified")

	if options.gnmap_path:
		addresses = gnmap_parse(options.gnmap_path)
	elif options.txt_path:
		addresses = txt_parse(options.txt_path)

	addresses.sort(key=lambda ip: map(int, ip.split('.')))
	print str(len(addresses)) + " addresses found"
	print "Processing addresses..."
	validaddresses = []
	falsepositives = []
	validrange = []
	workingaddress = ""
	for address in addresses:
		if not workingaddress:
			workingaddresslist = address.split(".")
			workingaddress = ".".join(workingaddresslist[0:3]) 
			validrange = [address]
		else:
			if re.match(workingaddress+"\.[0-9]+", address) is not None:
				validrange.append(address)
			else:
				if len(validrange) < int(options.count):
					print "Valid address range " + workingaddress + ".0/24 found"
					validaddresses.append(validrange)
				else:
					falsepositives.append([workingaddress + ".0/24])
				workingaddresslist = address.split(".")
				workingaddress = ".".join(workingaddresslist[0:3]) 
				validrange = [address]
	
	create_output_file(options.output_path, validaddresses, options.count)
	if options.false_output_path:
		create_output_file(options.false_output_path, falsepositives, options.count)
	
if __name__ == "__main__":
    main()
