#@author: Giorgio Di Tizio

import re
from adblockparser import AdblockRules
from DBCrawlerSqlite import DBconnection
import os 
from time import sleep
import sys

db = None
WRONG = "Something wrong happened :((\n"
inclusion = "\"Inclusion\""
redirection = "\"Redirection\""
link = "\"Link\""
link_cookie = "\"Link Cookie\""
access = "\"Access\""
access_cookie = "\"Access Cookie\""
cookie_sync = "\"Cookie Syncing\""
cookie_fwd = "\"Cookie Forwading\""
knows = "\"Knows\""

#mitigations
disconnect="disconnect"
ghostery="ghostery"
adblock="adblock"
elep="elep"
privacybadger="privacybadger"
privacybadger_file="PrivacyBadgerTop200.txt"
disconnect_file="Disconnect.txt"
adblock_file="Adblockplus.txt"
ghostery_file="Ghostery.txt"
ELEP_file = "Adblockplus_extended_2019.txt"
#by default we expect to test with the old one 
mitigation_type = 'old'
domain_blacklisted_file = "dom_blocked.txt"
domain_cookieblocked_file = "dom_cookieblocked.txt"
third_no_visited=False
mitigations=[]
blacklisted =[]
rules = []
blocked_cookies = []
visited_website = []


#number of web site to visit
numb_webs = 0

#initialize the DB pointer
def initialize():
    global db
    db = DBconnection()

def close_connection():
    global db
    if db!=None:
        db.closeconnection()

def main():
	global disconnect_file
	global adblock_file
	global ghostery_file
	global mitigation_type
	#initialize DB to query
	initialize()

	if len(sys.argv)<4:
		print("Usage: python formal_model_extraction.py mitigation('' if none) number_websites new/old")
		exit(1)

	mitigations.append(sys.argv[1])
	numb_webs = int(sys.argv[2])

	if sys.argv[3]=='new':
		disconnect_file="Disconnect_2019.txt"
		adblock_file="Adblockplus_2019.txt"
		ghostery_file="Ghostery_2019.txt"
		#privacy budget doesnt change
		privacybadger_file="PrivacyBadgerTop200.txt"
		mitigation_type='new'
	elif sys.argv[3]=='old':
		disconnect_file="Disconnect.txt"
		adblock_file="Adblockplus.txt"
		ghostery_file="Ghostery.txt"
		privacybadger_file="PrivacyBadgerTop200.txt"
		mitigation_type='old'
	else:
		print("Wrong version of mitigation: insert 'new' or 'old'")
		exit(1)

	#initialize blacklisted domain based on the mitigations
	generate_extensions(mitigations)

	#drop all the old .csv file
	for file in os.listdir('.'):
		if re.search('.csv',file):
			os.remove(os.path.join('.',file))

	global visited_website	
	#by default Firefox uses Google Search engine therefore google(.com) is visited
	visited_website.append('google.com')

	for website in range(1,1+numb_webs):	
		#add the web site to the list
		db.get_website(website)
		webs = db.get_result()
		#drop http protocol
		webs = re.split('://',webs)[1]
		visited_website.append(webs)
		

	visited_website = list(set(visited_website))

	#do a different for to have the entire list of visited_website before doing any computation (e.g. it is needed for block third-party content from domain not visited, here we assume these domain are already visited one time)

	for website in range(1,1+numb_webs):
		#extract redirects and inclusion from the DB
		db.get_responses(website)
		lines = db.get_results_columns()

		#convert ID to domain name
		lines = convert_to_name(lines)

		#generate csv with tracking flow rules
		with open('edges_tracking_flow.csv','a') as tracking_csv:
			while lines!=[]:
				#get the first line, we will drop it, therefore we will iterate over the other elements
				line = lines[0]

				if line[2]>300 and line[2]<400:
					#found a redirection
					tmp_lines = [line]
					#drop this line because we already match it
					lines.remove(line)
					#follow the redirections, object like lists are passed as references, therefore it will be modified
					tmp = follow_redirection(lines,line[3])
					#add to the tmp lines
					tmp_lines = tmp_lines + tmp
					#write the redirection to file
					#call function to write the sequence of redirections
					resulting_lines = write_redirections(tmp_lines)
					for resulting_line in resulting_lines:
						tracking_csv.write(resulting_line)
				else:
					#found either a 200 or something else (e.g. 500,etc)
					#it is a direct inclusion therefore no need to follow the redirections
					resulting_lines = write_inclusion(line)
					tracking_csv.write(resulting_lines)
					#drop the line to continue
					lines.remove(line)
	print("Wrote tracking_flow file")

	#generate csv with corresponding Link predicates
	with open('edges_link.csv','a') as link_csv:
		with open('edges_tracking_flow.csv','r') as tracking_csv:
			lines = tracking_csv.readlines()
			#load the domains that are known to implement cookie matching
			with open('cookie_matching_partners_bahsir.txt','r') as f:
				pairs = f.readlines()
				cookie_matching_known = []
				for pair in pairs:
					pair = pair.strip('\n')
					cookie_matching_known.append(pair)

			#statistics number of elements
			tmp_w = []
			tmp_w1 = []
			numb_include = 0;
			numb_redirect = 0;
			for line in lines:
				line = line.strip('\n')
				#split by comma
				line = re.split(',',line)
				#compute statistics
				tmp_w.append(line[0])
				tmp_w1.append(line[1])
				if line[2]==inclusion:
					numb_include+=1
				elif line[2]==redirection:
					numb_redirect+=1
				#convert Include and Redirection to Link and Link cookie
				#check if cookie syncing between the two domain has been detected, if yes add a Link_cookie
				line_cookie = check_sync_agreement(line,cookie_matching_known)
				if line_cookie!=None:
					link_csv.write(','.join(line_cookie)+'\n')

				#in any case add a Link (Link_cookie imply Link)
				line = convert_to_link(line)

				link_csv.write(','.join(line)+'\n')
			tmp_w = list(set(tmp_w))
			print(str(len(tmp_w)))
			tmp_w1 = list(set(tmp_w1))
			print(str(len(tmp_w1)))
			print("# of Include: "+str(numb_include))
			print("# of Redirect: "+str(numb_redirect))



	print("Wrote link file")

	#generate csv with corresponding Access predicate
	with open('edges_link.csv','r') as link_csv:
		with open('edges_access.csv','a') as access_csv:
			lines = link_csv.readlines()

			tmp_w = []
			tmp_w1 = []
			numb_link = 0
			numb_link_cookie = 0
			for line in lines:
				line = line.strip('\n')
				#split by comma
				line = re.split(',',line)

				tmp_w.append(line[0])
				tmp_w1.append(line[1])
				if line[2]==link:
					numb_link+=1
				elif line[2]==link_cookie:
					numb_link_cookie+=1
				#convert Include and Redirection to Link
				line = convert_to_access(line)

				if line!=None:
					access_csv.write(','.join(line)+'\n')

			tmp_w = list(set(tmp_w))
			print(str(len(tmp_w)))
			tmp_w1 = list(set(tmp_w1))
			print(str(len(tmp_w1)))
			print("# of Link: "+str(numb_link))
			print("# of Link Cookie: "+str(numb_link_cookie))

	print("Wrote access file")
	#generate cookie syncing
	with open('edges_access.csv','r') as access_csv:
		with open('edges_cookie_sync.csv','a') as sync_csv:
			lines = access_csv.readlines()

			#propagate access edges
			lines = propagate_access(lines)

			tmp_w = []
			tmp_w1 = []
			numb_access = 0
			numb_access_cookie = 0
			for line in lines:
				line = line.strip('\n')
				#split by comma
				line = re.split(',',line)

				tmp_w.append(line[0])
				tmp_w1.append(line[1])
				if line[2]==access:
					numb_access+=1
				elif line[2]==access_cookie:
					numb_access_cookie+=1

				#compute cookie syncing
				line = convert_to_sync_fwd(line)

				if line!=None:
					sync_csv.write(','.join(line)+'\n')

			tmp_w = list(set(tmp_w))
			print(str(len(tmp_w)))
			tmp_w1 = list(set(tmp_w1))
			print(str(len(tmp_w1)))
			print("# of Access: "+str(numb_access))
			print("# of Access Cookie: "+str(numb_access_cookie))

	print("Wrote cookie_sync file")

	#generate tracking via cookie syncing first and third party tracking
	with open('edges_cookie_sync.csv','r') as sync_csv:
		with open('edges_knows.csv','a') as knows_csv:
			lines = sync_csv.readlines()

			#propagate cookie sync
			lines = propagate_cookie_sync_fwd(lines)

			tmp_w = []
			tmp_w1 = []
			numb_sync = 0
			numb_fwd = 0
			for line in lines:
				line = line.strip('\n')
				#split by comma
				line = re.split(',',line)

				tmp_w.append(line[0])
				tmp_w1.append(line[1])
				if line[2]==cookie_sync:
					numb_sync+=1
				elif line[2]==cookie_fwd:
					numb_fwd+=1

				#convert to knows about
				line = convert_to_knows(line)

				if line!=None:
					knows_csv.write(','.join(line)+'\n')

			tmp_w = list(set(tmp_w))
			print(str(len(tmp_w)))
			tmp_w1 = list(set(tmp_w1))
			print(str(len(tmp_w1)))
			print("# of Cookie Sync: "+str(numb_sync))
			print("# of Cookie Forward: "+str(numb_fwd))

	print("Wrote knows file")


	#generate tracking via cookie sync: we will use the compact rule that allows to compute in a easier way the relations
	with open('edges_knows.csv','r') as knows_csv:
		with open('edges_final.csv','a') as final_csv:
			lines = knows_csv.readlines()

		
			lines = apply_cookie_sync_fwd(lines)

			for line in lines:
				line = line.strip('\n')
				#split by comma
				line = re.split(',',line)

				#mantain only knows edges
				line = filter_knows(line)

				if line!=None:
					final_csv.write(','.join(line)+'\n')

	print("END")




	#close DB connection
	close_connection()


#this function generate the sequence of redirections
def follow_redirection(lines,loc_id):
	#use for even if we modify lines because the recursion will work on the new list
	for line in lines:
		if line[1]==loc_id:
			#matched the next response of the redirection
			if line[2]>300 and line[2]<400:
				#matched another redirection
				#eliminate the line
				lines.remove(line)
				return [line]+follow_redirection(lines,line[3])
			else:
				#match a 200 or something else. Stop here
				#drop the line
				lines.remove(line)
				return [line]
		else:
			#didn-t matched, continue. We cannot eliminate it because the unmatched line can be used for other redirections or inclusions
			continue

	#it is possible that a response is missed (e.g. instagram)
	#in this case return an empty list
	return []


#create the blacklist given the mitigations implemented
def generate_extensions(mitigations):
	global rules
	global blocked_cookies
	global blacklisted
	global enabled_mitigation
	global third_no_visited

	if mitigations==['']:
		enabled_mitigation=False
		print("No mitigations enabled")
	if mitigations!=[]:
		enabled_mitigation = True
		for mit in mitigations:
			if mit==ghostery:
				print("Detected Ghostery mitigation")
				#add the uBlock list
				with open(ghostery_file,'r') as f:
					blocked = f.readlines()
					#strip \n
					blocked_list = []
					for e in blocked:
						#strip \n
						e = e.strip('\n')
						blocked_list.append(e)
					blacklisted = blacklisted+blocked_list
			elif mit==disconnect:
				print("Detected Disconnect mitigation")
				with open(disconnect_file,'r') as f:
					blocked = f.readlines()
					
					blocked_list = []
					for e in blocked:
						#strip \n
						e = e.strip('\n')
						blocked_list.append(e)
					blacklisted = blacklisted+blocked_list

			#generate rule that can be directly analyzed
			elif mit==adblock:
				print("Detected AdBlockplus mitigation")
				#add the Adblock list
				with open(adblock_file,'r') as f:
					blocked = f.readlines()
					
					blocked_list = []
					for e in blocked:
						#strip \n
						e = e.strip('\n')
						#depending if the file is from Bahsir or the new version we have a different format. Bahsir is like: 'doubleclick', while the commond Adblock file is like '||doubleclick/hello?file=track.js'
						#therefore we decided to extract only the domain name
						#eliminate || if present
						tmp_e = re.split("\|\|",e)
						#check if || was present, if yes then we have something like ['','doubleclick/hello?file=track.js']
						if len(tmp_e)>1:
							stripped_dom = tmp_e[1]
							#else it is not present so we have ['doubleclick']
						else:
							stripped_dom = tmp_e[0]
						#now eliminate anything that follow a /
						stripped_dom = re.split("/",stripped_dom)
						#get the first element in any case
						stripped_dom = stripped_dom[0]
						#append to the list
						blocked_list.append(stripped_dom)
					blacklisted = blacklisted+blocked_list
			#generate rule that can be directly analyzed
			elif mit==elep:
				print("Detected EasyList&EasyPrivacy mitigation")
				#add the EPEL list
				with open(ELEP_file,'r') as f:
					blocked = f.readlines()
					
					blocked_list = []
					for e in blocked:
						#strip \n
						e = e.strip('\n')
						#depending if the file is from Bahsir or the new version we have a different format. Bahsir is like: 'doubleclick', while the commond Adblock file is like '||doubleclick/hello?file=track.js'
						#therefore we decided to extract only the domain name
						#eliminate || if present
						tmp_e = re.split("\|\|",e)
						#check if || was present, if yes then we have something like ['','doubleclick/hello?file=track.js']
						if len(tmp_e)>1:
							stripped_dom = tmp_e[1]
							#else it is not present so we have ['doubleclick']
						else:
							stripped_dom = tmp_e[0]
						#now eliminate anything that follow a /
						stripped_dom = re.split("/",stripped_dom)
						#get the first element in any case
						stripped_dom = stripped_dom[0]
						#append to the list
						blocked_list.append(stripped_dom)
					blacklisted = blacklisted+blocked_list
			elif mit==privacybadger:
				print("Detected Privacy Badger mitigation")
				#in this case we can also have blockcookies so we enable the third_no_visited
				third_no_visited=True
				with open(privacybadger_file,'r') as f:
					blocked = f.readlines()
					#file is in the form: domain,block/cookieblock
					blocked_list = []
					for e in blocked:
						e = e.strip('\n')
						#split in domain and action
						e = re.split(',',e)
						domain = e[0]
						action = e[1]
						if action=='block':
							blocked_list.append(domain)
						elif action=='cookieblock':
							blocked_cookies.append(domain)
					blacklisted = blacklisted+blocked_list
		with open(domain_blacklisted_file,'w') as domain_blocked_file:
			for d_blocked in blacklisted:
				domain_blocked_file.write(d_blocked+'\n')
		
		with open(domain_cookieblocked_file,'w') as domain_blocked_file:
			for d_blocked in blocked_cookies:
				domain_blocked_file.write(d_blocked+'\n')

		#remove duplicates
		rules = list(set(blacklisted))
		

	else:
		enabled_mitigation=False
		print("No mitigations enable")

#mantain only knows edges
def filter_knows(line):
	if line[2]==knows:
		return line
	else:
		return None

#convert cookie syncing/fwd to knows
def apply_cookie_sync_fwd(lines):
	for line in lines:
		apply = False
		line = line.strip('\n')

		#split by comma
		line = re.split(',',line)
		source = line[0]
		dest = line[1]
		#apply if either cookie sync or cookie fwd
		if line[2]==cookie_sync:
			apply=True
		elif line[2]==cookie_fwd:
			apply=True

		if apply:
			#check if source has some knows with other nodes, if yes link to dest
			for line_2 in lines:
				line_2 = line_2.strip('\n')
				#split by comma
				line_2 = re.split(',',line_2)
				source_2 = line_2[0]
				dest_2 = line_2[1]
				if source_2==source:
					if line_2[2]==knows:
						new_line = dest+','+dest_2+','+knows+'\n'
						if new_line not in lines:
							lines.append(new_line)

	return lines

		

#convert Access to Knows
def convert_to_knows(line):
	if line[2]==access:
		#check that you visited the src, otherwise we are computing possible knows that are general
		if line[0] in visited_website:
			#line[1] knows you accessed line[0] if either no third-party blocking is enabled or the dest has been visited
			if third_no_visited:
				#check if has been visited
				if line[1] in visited_website:
					line[2]=knows
					#swap src and dst
					tmp = line[0]
					line[0]=line[1]
					line[1]=tmp
					return line
				else:
					#this is the case where we have third-party blocking cookie enabled (e.g. privacy badger) and we didn't visited directly that website. Now we need to check if the domain is blocked by privacy badger
					if line[1] in blocked_cookies:
						return None
					#else is not blocked
					else:
						line[2]=knows
						#swap src and dst
						tmp = line[0]
						line[0]=line[1]
						line[1]=tmp
						return line
			else:
				#no mitig
				line[2]=knows
				#swap src and dst
				tmp = line[0]
				line[0]=line[1]
				line[1]=tmp
				return line
		else:
			return None
	else:
		#probably a cookie sync, we will manage it later
		return line



#convert link and link_cookie to access, access_cookie if no extension block them
def convert_to_access(line):
	if enabled_mitigation:
		#if the mitigation we are considering are the new one then the blacklist rule must consider also what follow the .
		if mitigation_type=='new':
			#we require a complete match
			if line[1] in rules:
				return None
		elif mitigation_type=='old':
			#strip what follow the dot
			tmp_line = re.split(r'\.',line[1])
			#mantain only the first part of the domain (before the dot)
			tmp_line = tmp_line[0]
			#else we do not have info about what follow the . so we match independently from what follow the .
			if tmp_line in rules:
				return None

	#else it is not blocked by any extension or a mitigation is not present therefore convert to access		
	if line[2]==link:
		line[2]=access
	elif line[2]==link_cookie:
		line[2]=access_cookie
	else:
		print(WRONG)
		exit()

	return line


#convert access_cookie to cookie_sync if destination is not blocked
def convert_to_sync_fwd(line):
	if line[2]==access_cookie:
		#check if third-party cookie blocking from web site not visited is enabled
		if third_no_visited:
			#mitigation is implemented
			#check if the destination domain has been visited previously
			if line[1] in visited_website:
				#then it is allowed to store cookie and therefore implement cookie sync
				line[2]=cookie_sync
				return line
			else:
				#not visited so cannot set cookies if blocked by e.g. privacy badger -> therefore no cookie sync but cookie forwarding
				if line[1] in blocked_cookies:
					line[2]=cookie_fwd
					return line
				#else it is not blocked by the protection
				else:
					line[2]=cookie_sync
					return line
		else:
			#no mitigation then directy cookie sync
			line[2]=cookie_sync
			return line
	else:
		#otherwise return the line without modification
		return line


#this function allows to propagate the access 
def propagate_access(lines):
	new_size = len(lines)+1
	size = len(lines)
	while new_size>size:
		size = new_size
		for line in lines:
			line = line.strip('\n')

			#split by comma
			line = re.split(',',line)
			source = line[0]
			dest = line[1]
			if line[2]==access:
				for line_2 in lines:
					line_2 = line_2.strip('\n')

					#split by comma
					line_2 = re.split(',',line_2)
					source_2 = line_2[0]
					dest_2 = line_2[1]

					if dest==source_2:
						if line_2[2]==access:
							new_line = source+','+dest_2+','+access+'\n'
							if new_line not in lines:
								lines.append(new_line)

		new_size = len(lines)

	return lines

#propagate cookie syncing and fwd
def propagate_cookie_sync_fwd(lines):
	#we propagate the edges to correcty compute the exchange of info due to a sequence of cookie_sync and cookie_fwd without relying on the sequence with which we compute the knows visit for the nodes
	new_size = len(lines)+1
	size = len(lines)
	while new_size>size:
		size = new_size
		for line in lines:
			line = line.strip('\n')

			#split by comma
			line = re.split(',',line)
			source = line[0]
			dest = line[1]
			if line[2]==cookie_sync:
				for line_2 in lines:
					line_2 = line_2.strip('\n')

					#split by comma
					line_2 = re.split(',',line_2)
					source_2 = line_2[0]
					dest_2 = line_2[1]

					if dest==source_2:
						if line_2[2]==cookie_sync:
							new_line = source+','+dest_2+','+cookie_sync+'\n'
							if new_line not in lines:
								lines.append(new_line)
						elif line_2[2]==cookie_fwd:
							#this operation could generate redundancy in the computation of the knows visit but we will consider only one single instance of known therefore the redundancy will be eliminated
							new_line = source+','+dest_2+','+cookie_fwd+'\n'
							if new_line not in lines:
								lines.append(new_line)
			
			elif line[2]==cookie_fwd:
				for line_2 in lines:
					line_2 = line_2.strip('\n')

					#split by comma
					line_2 = re.split(',',line_2)
					source_2 = line_2[0]
					dest_2 = line_2[1]

					if dest==source_2:
						if line_2[2]==cookie_sync:
							#this operation could generate redundancy in the computation of the knows visit but we will consider only one single instance of known therefore the redundancy will be eliminated
							new_line = source+','+dest_2+','+cookie_fwd+'\n'
							if new_line not in lines:
								lines.append(new_line)
						elif line_2[2]==cookie_fwd:
							#this operation could generate redundancy in the computation of the knows visit but we will consider only one single instance of known therefore the redundancy will be eliminated
							new_line = source+','+dest_2+','+cookie_fwd+'\n'
							if new_line not in lines:
								lines.append(new_line)

		new_size = len(lines)

	return lines


def check_sync_agreement(line,cookie_matching_known):
	#check if the two domains are involved in known cookie matching
	#if yes, then this is a Link_cookie
	#drop top level domain because it is not present in the cookie matching list
	tmp_line0 = re.split(r'\.',line[0])[0]
	tmp_line1 = re.split(r'\.',line[1])[0]
	#try both combination, we assume symmetric cookie matching
	string = tmp_line0+" "+tmp_line1
	string2 = tmp_line1+" "+tmp_line0
	if string in cookie_matching_known:
		line[2]=link_cookie
		return line
	elif string2 in cookie_matching_known:
		line[2]=link_cookie 
		return line
	else:
		return None

#convert inclusion and redirection to Link
def convert_to_link(line):
	if line[2]==inclusion:
		#write access
		line[2]=link
	elif line[2]==redirection:
		line[2]=link
	#case in which a link cookie has been generated previously, in this case we have Link_cookie->Link therefore just generate it
	elif line[2]==link_cookie:
		line[2]=link
	else:
		print(WRONG)
		print(line[2])
		exit(1)

	return line

#convert the ID to the corresponding name of domain (stripping of urls)
def convert_to_name(lines):
	converted_lines=[]
	for line in lines:
		line = list(line)
		#get the name of the target web sites visited
		db.get_site_visits(line[0])
		name = db.get_result()
		line[0] = extract_domain(name)

		#get urls of the resources contacted
		#db.get_url(line[1])
		tmp1 = line[1]
		line[1] = extract_domain(tmp1)
		if line[3]!=None:
			if line[3]!='':
				tmp2 = line[3]
				line[3] = extract_domain(tmp2)

		line = tuple(line)
		converted_lines.append(line)

	return converted_lines

#extract the domain from an url, consider only up to the second level
def extract_domain(url):
	global visited_website	
	if url.startswith('data:'):
		return ''
	if url.startswith('http'):
		content = re.split('://',url)
		content = re.split('/',content[1])
		content = content[0]
		content = content.replace('www.','')
	elif url.startswith('//'):
		content = re.split('//',url)
		content = re.split('/',content[1])
		content = content[0]
		content = content.replace('www.','')
	elif url.startswith('/'):
		#local value in some folder so ignore it
		return ''


	
	if content in visited_website:
	#if it is a visited web site can have more than 2 dots
		return content

	#consider only the path up to 2 dot
	content = re.split(r'\.',content)
	while len(content)>2:
		content = content[1:]
		#check if it s now reduced to a domain directly visited, if so it is also fine that it s not only two dot
		content = '.'.join(content)
		if content in visited_website:
		#if it is a visited web site can have more than 3 dots
			return content
		else:
			content = re.split(r'\.',content)


	content = '.'.join(content)

	return content


#create a string representing the inclusion
def write_inclusion(line):
	resulting_lines = str(line[0])+','+str(line[1])+','+inclusion+'\n'
	return resulting_lines

#create a sequence of strings for inclusion and redirections
def write_redirections(lines):
	resulting_lines = []
	#the first is composed by an inclusion and a redirection
	line = lines[0]
	line1 = str(line[0])+','+str(line[1])+','+inclusion+'\n'
	line2 = str(line[1])+','+str(line[3])+','+redirection+'\n'
	resulting_lines.append(line1)
	resulting_lines.append(line2)

	#drop the first line and iterate over the other lines (only redirection+final url reached)
	lines = lines[1:]
	for line in lines:
		#if None means we reached the end of the sequence of redirections
		if line[3]!=None:
			tmp_line = str(line[1])+','+str(line[3])+','+redirection+'\n'
			resulting_lines.append(tmp_line)

	return resulting_lines

if __name__ == '__main__':
	main()
