#@author: Giorgio Di Tizio

import re
import sys
import os

#rules: the rules are already present in the axioms.ax file
axiom_file = 'axioms.ax'
#type of relationship
inclusion = "\"Inclusion\""
redirection = "\"Redirection\""

#files
tmp_problem_input = "problem_tmp.p"
problem_input_no_dupl = "problem_no_dupl.p"
problem_input = "problem_input.p"

#cookie sync from previous works
cookie_sync_file = "cookie_matching_partners_bahsir.txt"
include_redirect_file = "edges_tracking_flow.csv"
domain_blocked_file = "dom_blocked.txt"

var='var'
number = 1
complete_match = False


#initialize the DB pointer
def initialize():
    global db
    db = DBconnection()

def close_connection():
    global db
    if db!=None:
        db.closeconnection()

#we get the data from the script formal_model_extraction.py that generates different files among which the include and redirect relationships and the blocked domains by the extensions
def main():
	global complete_match
	if len(sys.argv)<3:
		print('Usage: python proof_problem_generation.py domain_tracker domain_tracked')
		exit(1)
	#get the list of domains considered
	domains = []
	with open(include_redirect_file) as file:
		lines = file.readlines()
		for line in lines:
			line = re.split(',',line)
			if line[0] not in domains:
				domains.append(line[0])
			if line[1] not in domains:
				domains.append(line[1])

	#create the instances of the domains that are not blocked
	#read the domains blocked and then check if each domain visited is present in the list
	domains_blocked = []
	with open(domain_blocked_file) as file:
		lines = file.readlines()
		for line in lines:
			line = line.strip('\n')
			#check if the domain in the filter list contains the top level domains i.e. are in the format: 'google.com' or 'google'
			if not(complete_match):
				if len(re.split(r'\.',line))>1:
					#set that the check to block the domain must match also the TLD
					complete_match = True
			domains_blocked.append(line)


	domains_not_blocked = []
	for d in domains:
		if complete_match:
			if d not in domains_blocked:
				domains_not_blocked.append(d)
		else:
			#we need to do a partial match so we need to strip everything that follow the dot
			tmp_d = re.split(r'\.',d)
			#take only the first part i.e. if we have 'google,com' then d=['google','com']
			tmp_d = tmp_d[0]
			if tmp_d not in domains_blocked:
				domains_not_blocked.append(d)

	#clean old files
	open(tmp_problem_input, 'w').close()
	open(problem_input_no_dupl, 'w').close()
	open(problem_input, 'w').close()

	#add redirection and inclusion
	add_include_redirect_domains()
	#add not blocked domains
	add_not_blocked_domains(domains_not_blocked)
	#add not blocked cookies: in our experiment it is always the case, so we pass domains i.e. all the domains
	add_not_blocked_cookie(domains)
	#write red_cookie from cookie sync
	add_redirect_cookie(domains)

	#add that the website is visited otherwise a rule will not be triggered
	add_visited(sys.argv[2])

	add_goal(sys.argv[1],sys.argv[2])

	add_inclusion_axioms()

	#now eliminate duplicate lines
	with open(problem_input_no_dupl,'w') as file, open(tmp_problem_input,'r') as f:
		lines_seen = []
		lines = f.readlines()
		for line in lines:
			if line in lines_seen:
				continue
			else:
				lines_seen.append(line)
		for l in lines_seen:
			file.write(l)

	with open(problem_input_no_dupl,'r') as file,  open(problem_input,'w') as final_file:
		#now we need to assign an unique value for each fof (we didn't do before because otherwise the elimination procedure would not work)
		lines = file.readlines()
		for line in lines:
			new_line = line.replace('var,',var+str(get_number())+',')
			final_file.write(new_line)

def get_number():
	global number
	returned_number = number
	number += 1
	return returned_number

def add_inclusion_axioms():
	with open(tmp_problem_input,'a') as file:
		string = "include('examples/tptp/%s').\n" % (axiom_file)
		file.write(string)

def add_visited(domain):
	with open(tmp_problem_input,'a') as file:
		string = "fof(%s,axiom,(visit(\"%s\"))).\n" % (var, domain)
		file.write(string)

def add_include_redirect_domains():
	with open(tmp_problem_input,'a') as f:
		with open(include_redirect_file) as file:
			lines = file.readlines()
			for line in lines:
				line = re.split(',',line)
				line[2] = line[2].strip('\n')
				if line[2]==inclusion:
					string = "fof(%s,axiom,(includeContent(\"%s\",\"%s\"))).\n" % (var, line[0], line[1])
				elif line[2]==redirection:
					string = "fof(%s,axiom,(redirect(\"%s\",\"%s\"))).\n" % (var, line[0], line[1])
				f.write(string)


def add_not_blocked_domains(domains):
	with open(tmp_problem_input,'a') as f:
		for d in domains:
			string = "fof(%s,axiom,(~block_requests(\"%s\"))).\n" % (var, d)
			f.write(string)

def add_not_blocked_cookie(domains):
	with open(tmp_problem_input,'a') as f:
		for d in domains:
			string = "fof(%s,axiom,(~block_tp_cookie(\"%s\"))).\n" % (var, d)
			f.write(string)

#we decided to create only redirects from cookie sync even if it s possible that they are generated through IncludeContent_cookie. But the result is the same
def add_redirect_cookie(domains):
	with open(tmp_problem_input,'a') as f:
		#create redirect_cookies from cookie sync information
		with open(cookie_sync_file) as file:
			lines = file.readlines()
			for line in lines:
				line = re.split(' ',line)
				#the cookie matching data misses the top level domain so we need to check which tld is from the domains we have (furthemore if we do not find any domain we avoid to create this entry)
				for d in domains:
					#strip the tld
					tmp_domain = re.split(r'\.',d)[0]
					if line[0]==tmp_domain:
						for d1 in domains:
							tmp_domain1 = re.split(r'\.',d1)[0]
							if line[1]==tmp_domain1:
								#consider the cookie sync symmetric i.e. done in both directions
								string1 = "fof(%s,axiom,(redirect_cookie(\"%s\",\"%s\"))).\n" % (var,d, d1)
								string2 = "fof(%s,axiom,(redirect_cookie(\"%s\",\"%s\"))).\n" % (var,d1, d)
								f.write(string1)
								f.write(string2)

def add_goal(domain1,domain2):
	with open(tmp_problem_input,'a') as f:
		string = "fof(%s,conjecture,(knows(\"%s\",\"%s\"))).\n" % (var,domain1, domain2)
		f.write(string)

if __name__ == '__main__':
	main()
