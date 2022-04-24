# email_analyzer.py
#################################################################################################
# 
# Author: Mr.AnyThink
# usage: email_forensics.py -f <.eml file name> [-s <number_of_action>]
# It work in python 2.7. If you are on python3 make sure you are creating virtualenvironment for python2.7. To create follow below
# virtualenv -p /usr/bin/python2.7 venv => create virtual environment for python2.7
# . venv/bin/activate => Activate virutal environment
# Then install tabulate with command "pip install tabulate"
#
#################################################################################################**

usage:
	python email_analyzer.py -f <email_file> [-s <select_operation> ]
	
	-f	Specify email file to analyse.
	-s	Select operation to get details.
	-h	Get help
	
Example: 
	python email_analyzer.py -f email.eml
	python email_analyzer.py -f email.eml -s 1
