#!/usr/bin/python
# -*- coding: UTF-8 -*-
''' 
The main porpouse of this program is:

Parses the RLM ReportLog file (*.rl) into a CSV format.
Search records for checkin, checkout e deny (OUT, IN or DENY) separately because each 
record has your own output format
There's no option now, to output ALL records together.

usage: rlmlog.py [-h] [-y YEAR | -d SDATE] [-u SUSER] [-t REG_TYPE] [-v]
                 [filename]

positional arguments:
  filename           The input log file to be parsed. REQUIRED

optional arguments:
  -h, --help         show this help message and exit
  -y YEAR            Year (YYYY) you want to search.
  -d SDATE           Date (MMDDYYYY) you want to search.
  -u SUSER           User you want to search.
  -t REG_TYPE        Type of record you want: [IN, OUT or DENY]. REQUIRED
  -v, -V, --version  show program's version number and exit


'''

import sys
import argparse
import re

_count_print = 0
_head_in = True
_head_out = True
_head_deny = True
# Colors
_RED_font  = "\033[1;31;48m"
_NORM_bg   = "\033[0;37;48m"

# Why Reason Dictionary
wreason = {
				# Why Reason
				'1': 'Normal checkin by application',
				'2': 'Application exited, automatic checkin',
				'3': 'License removed by (rlmremove) utility',
				'4': 'License removed by server after timeout',
				'5': 'License hold/minimum checkout period expired',
				'6': 'Client requested license dequeue',
				'7': 'Portable hostid removed',
				'8': 'Failed host back up',
				'9': 'Server lost its transferred licenses',
				'10': 'Meter ran out of count during a periodic decrement',
				# RML Status
				'0':"Success",
				'-22':"All licenses in use",
				'-44':"Application is inactive",
				'-7':"bad date format - not permanent or dd-mm-yy",
				'-43':"bad hostname in license file or port@host",
				'-5':"Bad key in authorization",
				'-41':"Bad parameter to rlm_checkout() call",
				'-6':"Requested version not supported",
				'-38':"time() call failure",
				'-17':"Error communicating with server",
				'-3':"Authorization has expired",
				'-25':"In queue for license",
				'-21':"No heartbeat response received",
				'-23':"No hostid on uncounted license",
				'-28':"Server does not know this license handle",
				'-18':"License server doesn't support this",
				'-9':"No license auth supplied to call",
				'-19':"No license handle",
				'-1':"No authorization for product",
				'-42':"Roam operations not allowed on failover server",
				'-13':"Not on the feature include list",
				'-12':"Not on the includeall list",
				'-30':"Not on the roam include list",
				'-45':"User is not on the named-user list",
				'-37':"License start date in the future",
				'-4':"Wrong host for authorization",
				'-2':"Authorization is for another ISV",
				'-10':"On excludeall list",
				'-29':"On roam exclude list",
				'-11':"On feature exclude list",
				'-14':"Request would go over license MAX",
				'-39':"Request goes over license soft_limit",
				'-15':"License (rlm)removed by server",
				'-34':"Cannot check out rlm_roam license",
				'-27':"Roam time exceeds maximum",
				'-33':"Problem with roam file",
				'-16':"Unexpected response from server",
				'-20':"Server closed connection",
				'-26':"License syntax error",
				'-24':"License timed out by server",
				'-8':"checkout request for too many licenses",
				'-31':"Too many licenses roaming already",
				'-46':"Terminal server/remote desktop disabled",
				'-32':"License expires before roam period ends",
				'-40':"Clock setback detected",
				'-35':"Wrong platform for client",
				'-36':"Wrong timezone for client"
				}

def open_file(filename):
	''' Open a file '''
	try:
		filehandle = open(filename, 'r')
		return filehandle
	except IOError as e:
		#print "I/O error({0}): {1} - {2}".format(e.errno, filename, e.strerror)
		mesg("I/O error({0}): {1} - {2}".format(e.errno, filename, e.strerror))
		sys.exit()
	except:
		mesg("Unexpected error: {0}".format(sys.exc_info()[0]))
		sys.exit()


def parse_IN(linefld, suser, ano):
	''' Parse IN line and reason 'why' '''
	global _count_print
	global _head_in
	# Tranform the line into a list
	reg = linefld.split()
	# why descriptio from dict
	reg[1] = wreason[reg[1]]
	# Position in field mm/dd to insert yyyy
	pos = len(reg) - 2
	# insert the year (yyyy) adding month and day
	reg[pos] = ano + "/" + reg[pos]
	# Get the username
	user = reg[4]
	# If suser id None (the flag -u wasn't completed),
	# then suser is equal user
	if suser is None:
		suser = user
	# Comprare user and suser.
	if suser == user:
		# Prints the hard on the first time 
		if _head_in is True:
			print ('IN;why;product;version;user;host;"isv_def";count;cur_use;cur_resuse;'
				      'server_handle;yyyy/mm/dd;hh:mm:ss')
			_head_in = False

		# Prints the result in string format
		print '{0};{1}'.format(ano, ';'.join(reg))
		_count_print = 1



def parse_OUT(linefld, suser, ano):
	''' Parse OUT line	 See comments in parse_IN'''
	global _count_print
	global _head_out
	reg = linefld.split()
	pos = len(reg) - 2
	reg[pos] = ano + "/" + reg[pos]
	user = reg[4]
	if suser is None:
		suser = user
	if suser == user:
		if _head_out is True:
			print ('OUT;product;version;pool#;user;host;"isv_def";count;cur_use;cur_resuse;'
				      'server_handle;share_handle;process_id;"project";"requested;product";'
				      '"requested version";yyyy/mm/dd;hh:mm:ss')
			_head_out = False

		print '{0};{1}'.format(ano, ';'.join(reg))
		_count_print = 1


def parse_DENY(linefld, suser, ano):
	''' Trata linha de DENY	'''
	global _count_print
	global _head_deny
	reg = linefld.split()
	# Get form last position - 4, the why reason
	pos = len(reg) - 4
	reg[pos] = wreason[reg[pos]]
	pos = len(reg) - 2
	reg[pos] = ano + "/" + reg[pos]
	#
	user = reg[3]
	if suser is None:
		suser = user
	if suser == user:
		if _head_deny is True:
			print 'DENY;product;version;user;host;"isv_def";count;why;last_attempt;yyyy/mm/dd;hh:mm'
			_head_deny = False

		print '{0};{1}'.format(ano, ';'.join(reg))
		_count_print = 1
 

def exit_mesg(fhandle, flag_f):
	''' Verifica se existe registro no arquivo de log '''
	if flag_f is False:
		mesg("None was found in log file")

	fhandle.close()
	sys.exit()

def mesg(phrase):
	''' Print one message in Red '''
	print "\n" + _RED_font + phrase + "\n" + _NORM_bg


def main():
	''' execução principal '''
	# ArgParser
	parser = argparse.ArgumentParser()
	group = parser.add_mutually_exclusive_group()
	group.add_argument('-y', help='Year (YYYY) you want to search.',
	                   action='store', dest='year', default='0')
	group.add_argument('-d', help='Date (MMDDYYYY) you want to search.',
	                   action='store', dest='sdate')
	parser.add_argument('-u', help='User you want to search.',
	                    action='store', dest='suser')
	parser.add_argument('-t', help='Type of record you want: [IN, OUT or DENY]. REQUIRED',
	                    action='store', dest='reg_type')
	parser.add_argument('-v', '-V', '--version', action='version', version='%(prog)s 0.5.18.17')
	parser.add_argument('filename', help='The input log file to be parsed. REQUIRED', nargs='?')

	args = parser.parse_args()

	# Parsing Args
	ano_search = args.year
	date_search = args.sdate
	suser = args.suser
	reg_type = args.reg_type
	filename = args.filename
	ano_atual = 0
	ano_anterior = 0
	flag_found = False
	flag_sdate = False
	search_all = False

	# Possibles mistakes

	# Call help if there is no filename
	#if _name_file or _path_name_file is None:
	if filename is None:
		mesg('Missing <filename>. Do not forgot the path before filename!')
		parser.parse_args(['-h'])
		sys.exit()

	if date_search is not None:
		smonth = date_search[:2]
		sday = date_search[2:4]
		syear = date_search[4:]
		ano_search = syear
		flag_sdate = True

	if reg_type is None:
		mesg('Missing a type of record (IN, OUT or DENY).')
		parser.parse_args(['-h'])
		sys.exit()

	reg_type = reg_type.upper()

	if reg_type not in ['IN', 'OUT', 'DENY']:
		mesg('Missing a type of record (IN, OUT or DENY).')
		parser.parse_args(['-h'])
		sys.exit()

    # Open the file
	fh = open_file(filename)

	for line in fh:
		date = line.split()
		# Search lines begining with date (MM/DD/YYYY), to process the year part
		# This lines came before of the informations about license use.
		if  re.match('\d{2}/\d{2}/\d{4}', line):
			ano_atual = date[0].split('/')[2]
			mes_atual = date[0].split('/')[0]
			dia_atual = date[0].split('/')[1]

			if ano_atual == ano_anterior:
				continue
			else:
				ano_anterior = ano_atual


			# If theres no year deafult for search, consider the atual year and search for all years
			if ano_search == '0':
				ano_search = ano_atual
				search_all = True

			# Compare if  ano_search is less than the first reg 
			if ano_search < ano_atual:
				# If not found
				if flag_found is False:
					exit_mesg(fh, flag_found)
				elif search_all is True:
					ano_search = ano_atual
				else:
					exit_mesg(fh, flag_found)



	# This is not a line date
	# Ignor lines that is no IN, OU or DENY
		if not (line.startswith('IN') or line.startswith('OUT') or line.startswith('DENY')):
			continue


		if ano_search == ano_atual:
			flag_found = True
			if flag_sdate is True:
				if mes_atual != smonth or dia_atual != sday:
					continue

			if line.startswith('IN '):
				if reg_type == 'IN':
					parse_IN(line, suser, ano_atual)
					continue
			elif line.startswith('OUT '):
				if reg_type == 'OUT':
					parse_OUT(line, suser, ano_atual)
					continue
			elif line.startswith('DENY '):
				if reg_type == 'DENY':
					parse_DENY(line, suser, ano_atual)
					continue
			else:
				continue

	# If never print any output, ends with error
	if _count_print == 0:
		flag_found = False

	exit_mesg(fh, flag_found)

#### MAIN ####
# Call the main function encapsulate in a try/except to catch the Ctrl+C
if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		mesg("\nInterupted by user!!")
		sys.exit()
