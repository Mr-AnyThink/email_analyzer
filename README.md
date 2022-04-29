**Email Analyzer:**

Author: Mr.AnyThink

A python script that allows you to extracts the relevant data that can be used later on in many ways such as reporting and incident responses. It can fetch and provide crucial email details which can be used in email forensics. It has ability to:

1. Extract Attachment (provides SHA256)
2. Extract URLs
3. Provide details such hops visited by email, Sender, Receipents, reply to etc.

This is very usefull for SOC analyst who works with SPAM, phishing emails on daily basis, where we want to get all details without opening the email. To use this script:

Clone repository with:

	https://github.com/Mr-AnyThink/email_analyzer.git

Install the dependencies with:

	pip3 install -r requirements.txt


usage:

	python email_analyzer.py -f <email_file> [-s <select_operation> ]
	
	-f	Specify email file to analyse.
	-s	Select operation to get details.
	-h	Get help
	
Example: 

	python3 email_analyzer.py -f email.eml
	python3 email_analyzer.py -f email.eml -s 1
