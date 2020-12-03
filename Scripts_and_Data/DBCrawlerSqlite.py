#@author: Giorgio Di Tizio

#this python file contains the definition of the class DBConnection; this class allows to create an object that contains all the operations to connect, create and load data into the DB

#DATABASE DEFINITION

import sqlite3
from sqlite3 import Error


db_file = "./sample_2018-06_1m_stateless_census_crawl.sqlite"

class DBconnection:
    def __init__(self):
        try:
            self.conn = None

            # connect to the DB passing the required information
            self.conn = sqlite3.connect(db_file)
            self.cur = self.conn.cursor()

        except Error as e:
            print(e)


    
    #this function allows to get the result of a query
    def get_result(self):
        id = self.cur.fetchone()
        if id!=None:
            return id[0]
        else:
            return None

    #this return only the first column
    def get_results(self):
        result = []
        id = self.cur.fetchall()
        for element in id:
            result.append(element[0])
        return  result

    #this allows to return all the columns of a query
    def get_results_columns(self):
        return self.cur.fetchall()

    def get_responses(self,visit_id):
        get_responses = 'SELECT visit_id,url,response_status,location FROM http_responses WHERE visit_id=\'%s\' ORDER BY time_stamp' % visit_id
        self.cur.execute(get_responses)

        #for the new DB structure. Here we now have url as a string and not an ID!!!
        #'SELECT visit_id,url,response_status,location FROM http_responses ORDER BY time_stamp' % visit_id

    def get_site_visits(self,site_id):
       get_site = 'SELECT site_url FROM site_visits WHERE visit_id=\'%s\'' % site_id
       self.cur.execute(get_site)

       #for the new DB structure. Here we just changed the names
       #'SELECT site_url FROM site_visits WHERE visit_id=\'%s\'' % site_id

    def get_url(self,url_id):
       get_url = 'SELECT url FROM urls WHERE id=\'%s\'' % url_id
       self.cur.execute(get_url)

       #for the new DB is not necessary anymore

       #REPEATED 
    def get_website(self,website_id):
       get_website = 'SELECT site_url FROM site_visits WHERE visit_id=\'%s\'' % website_id
       self.cur.execute(get_website)

       #for the new DB 
       #'SELECT site_url FROM site_visits WHERE visit_id=\'%s\'' % website_id

    def get_redirections(self,website_id):
        get_redirections = 'SELECT old_request_url,new_request_url FROM http_redirects WHERE visit_id=\'%s\'' % website_id
        self.cur.execute(get_redirections)
    
    def get_domain_response_cookies(self,website_id):
        get_domain = 'SELECT DISTINCT http_response_cookies.domain FROM http_response_cookies INNER JOIN http_requests ON http_response_cookies.response_id = http_requests.id WHERE http_requests.visit_id=\'%s\'' % website_id
        self.cur.execute(get_domain)

    def get_url_request_cookies(self,website_id):
        get_domain = 'SELECT http_requests.url_id FROM http_requests INNER JOIN http_request_cookies ON http_requests.id=http_request_cookies.request_id WHERE http_requests.visit_id=\'%s\'' % website_id
        self.cur.execute(get_domain)

    def get_domain_flash_cookies(self,website_id):
        get_domain = 'SELECT DISTINCT domain FROM flash_cookies WHERE visit_id=\'%s\'' % website_id
        self.cur.execute(get_domain)

    def get_url_fingerprint(self,website_id):
        get_url = 'SELECT url_id FROM javascript WHERE visit_id=\'%s\'' % website_id
        self.cur.execute(get_url)

    def closeconnection(self):
        if self.conn is not None:
            self.conn.close()
            print('DB connection closed')


