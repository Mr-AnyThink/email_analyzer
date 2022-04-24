**Email Analyzer:**

A python script that allows you to extracts the relevant data that can be used later on in many ways such as reporting and incident responses. It can fetch and provide crucial email details which can be used in email forensics. It has ability to:

1. Extract Attachment (provides SHA256)
2. Extract URLs
3. Provide details such hops visited by email, Sender, Receipents, reply to etc.

This is very usefull for SOC analyst who works with SPAM, phishing emails on daily basis, where we want to get all details without opening the email.

#################################################################

**email_analyzer.py**

#################################################################

Author: Mr.AnyThink

It works in python 2.7. If you are on python3 make sure you are creating virtualenvironment for python2.7. To create follow below

	# create virtual environment for python2.7
	virtualenv -p /usr/bin/python2.7 venv
	# Activate virutal environment
	. venv/bin/activate
	#Then install tabulate with command, as a prerquisite
	pip install tabulate

#################################################################

usage:

	python email_analyzer.py -f <email_file> [-s <select_operation> ]
	
	-f	Specify email file to analyse.
	-s	Select operation to get details.
	-h	Get help
	
Example: 

	python email_analyzer.py -f email.eml
	python email_analyzer.py -f email.eml -s 1
