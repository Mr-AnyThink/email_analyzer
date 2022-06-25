#################################################################################################
# 
# Author: Mr.AnyThink
# usage: email_forensics.py -f <.eml file name> [-s <number_of_action>]
# It work in python 2.7. If you are on python3 make sure you are creating virtualenvironment for python2.7. To create follow below
# virtualenv -p /usr/bin/python2.7 venv => create virtual environment for python2.7
# . venv/bin/activate => Activate virutal environment
# Then install tabulate with command "pip install tabulate"
#################################################################################################
import getopt
import email
import os
import re
import sys
from email.parser import HeaderParser
import hashlib
from tabulate import tabulate
import msg2eml

#######################
# count attachements
#######################
def count_attachment(mail):
    i = 0
    if mail.get_content_maintype() != 'multipart':
        return
    for part in mail.walk():
        if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
            i = i + 1
    return(i)

#######################
# extract attachments
#######################

def extractAttachments(mail):
    CWD = os.path.dirname(os.path.realpath(__file__)) #get current path
    outputdir = CWD + '/attachments'
    file_exists = os.path.exists(outputdir)
    if file_exists == False:
        os.mkdir(outputdir)

    i = 1
    if mail.get_content_maintype() != 'multipart':
           return
    for part in mail.walk():
           if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
                 open(outputdir + '/' + part.get_filename(), 'wb').write(part.get_payload(decode=True))
                 #calculate sha256 hash, of written file
                 sha256_hash = hashlib.sha256()
                 #get full file path
                 file_name = str(outputdir + '/' + part.get_filename())
                 with open(file_name, "rb") as f:
                    for byte_block in iter(lambda: f.read(4096),b""):
                        sha256_hash.update(byte_block)

                 f.close()
                 print (str(i) + ". " + part.get_filename() + " (SHA256: " + str(sha256_hash.hexdigest()) + " )")
                 i = i + 1
    print('\nAttachments are downloaded at: ' + outputdir + '\n')

#######################
# count URLs
#######################

def count_URLs(mail):
    i = 0
    for part in mail.walk():
        msg = str(part.get_payload(decode=True))
        urls_all = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',msg)
        if urls_all:
            unique_urls = set(urls_all)
            for url in unique_urls:
              i = i + 1
    return(i)

#######################
# extract URLs
#######################

def extractURLs(mail):
        for part in mail.walk():
                msg = str(part.get_payload(decode=True))
                urls_all = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',msg)
                if urls_all:
                      unique_urls = set(urls_all)
                      for url in unique_urls:
                         print (url + "\n")

##############################################
# Email Body
##############################################

def printBody(mail):
    body = ''
    if mail.get_content_maintype() != 'multipart':
                print(mail.get_payload(decode=True))
    else:
        for part in mail.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))

            # skip any text/plain (txt) attachments
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                        body = part.get_payload(decode=True)  # decode
                        break
        print(body)


##############################################
# extract Basic details from header
##############################################

def extractBasicHeader(mail):
    headers = HeaderParser().parsestr(str(mail), headersonly=True)
    To = "None"
    From = "None"
    CC = "None"
    Subject = "None"
    return_path = "None"
    reply_to = "None"
    spf = "None"
    xorgip = "None"
    xsenderip = "None"
    for key, value in headers.items():
        if str(key).lower() == 'to':
            To = value
        if str(key).lower() == 'from':
                From = value
        if str(key).lower() == 'cc':
                CC = value
        if str(key).lower() == 'subject':
                Subject = email.header.decode_header(value) 
                # Many time subnect is encoded, as mentioned below
                #=?utf-8?B?U3BhbTog4pyJIHRvbGxncm91cC5jb20gU3RvcmFnZSBSZS1WYWxpZGF0aW9u?=
                #=?utf-8?Q?_Of_Files_and_E-mail_Update.2021?=
        if str(key).lower() == 'reply-to':
                reply_to = value
        if str(key).lower() == 'return-path':
                return_path = value
        if str(key).lower() == 'authentication-results':
            spf = value.replace('\n', '')
        if str(key).lower() == 'x-originating-ip':
            xorgip = value
        if str(key).lower() == 'x-sender-ip':
            xsenderip = value
    return To, From, CC, str(Subject[0][0]).replace('\n', ''), reply_to, return_path, spf, xorgip, xsenderip

##############################################
# PrintHeader
##############################################

def printHeader(mail):
    headers = HeaderParser().parsestr(str(mail), headersonly=True)
    for key, value in headers.items():
        print (str(key) + ':' + str(value).replace('\n',''))

############################################################################################
# Print Hops
# This section read header line by line and extract hops from Received section
############################################################################################

def printHops(mail):
    headers = HeaderParser().parsestr(str(mail), headersonly=True)

    i = 0
    hops = []
    for key, value in headers.items():
        if str(key).lower() == 'received':
            hops.append([]) #create nested list, that store lists
            v = [] # create list to stores values
            #replace \n with null as vlaues contain newline which affects parsing
            v.append(re.findall('^from\s+(.*)by.*',value.replace('\n', ''))) #extract "from" value from received
            v.append(re.findall('.+by\s+(.*)\swith.*',value.replace('\n', ''))) #extract "by" from received
            v.append(re.findall('.+with\s+(.*)\sid.*',value.replace('\n', ''))) #extract "with (emailclient)" value from received

            for j in range(3):
                if j == 2:
                    hops[i].append(str(v[j]).replace(' ', '\n'))
                else:
                        hops[i].append(str(v[j]).replace('(', '\n('))

            i = i + 1
    hops = hops[::-1] #Reverse the list as list stored value top to bottom, Email hops are bottom to top
    head = ["From", "By", "With"]

    print(tabulate(hops, headers=head, tablefmt="grid"))

#######################
# get Source IP / Host
#######################

def getSource(mail):
    headers = HeaderParser().parsestr(str(mail), headersonly=True)

    i = 0
    hops = []
    for key, value in headers.items():
        if str(key).lower() == 'received':
            hops.append([]) #create nested list, that store lists
            v = [] # create list to stores values
            #replace \n with null as vlaues contain newline which affects parsing
            v.append(re.findall('^from\s+(.*)by.*',value.replace('\n', ''))) #extract "from" value from received
            v.append(re.findall('.+by\s+(.*)\swith.*',value.replace('\n', ''))) #extract "by" from received
            v.append(re.findall('.+with\s+(.*)\sid.*',value.replace('\n', ''))) #extract "with (emailclient)" value from received

            for j in range(3):
                if j == 2:
                    hops[i].append(str(v[j]).replace(' ', '\n'))
                else:
                        hops[i].append(str(v[j]).replace('(', '\n('))

            i = i + 1
    hops = hops[::-1] #Reverse the list as list stored value top to bottom, Email hops are bottom to top
    if len(hops) == 0:
        return "None"
    else:
        return hops[0][0]

#######################
# usage()
#######################

def usage():
    print("\n\t usage: \n\t\tpython email_analyzer.py -f <email_file> [-s <select_operation> ]  \n")
    print("\t\t-f\tSpecify email file to analyse.\n\t\t-s\tSelect operation to get details.\n\t\t-h\tGet help\n")
    print("\n\t Example: \n\t\tpython email_analyzer.py -f email.eml\n\t\tpython email_analyzer.py -f email.eml -s 1\n")


#######################
# main function
#######################

def main():
    opt_f = False
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "f:s:")
    except:
        usage()
        sys.exit(2)

    #check if file is provided
    for opt, arg in opts:
        if opt in ['-f']:
            opt_f = True

    if opt_f == False:
        exit("Email to analyze is missing !! Input it with \"-f\" option.\n")

    #eml = outlookmsgfile.load()

    for opt, arg in opts:
        if opt in ['-f']:
            emailinput = arg
            #Check if file is exists
            file_exists = os.path.exists(emailinput)
            if file_exists == False:
                exit("File Does Not Exists.\n")

            #check if file provided is .msg as it has different encoding and we must convert it to .eml
            check_msg = (re.findall('.*\.msg$',emailinput))
            if len(check_msg) > 0:
            	mail = msg2eml.load(emailinput)
            	#mail = emailfile
            else:
                #Read email file
                #emailfile = emailinput
                fp = open(emailinput)
                mail = email.message_from_file(fp)
                fp.close()

            url_count = count_URLs(mail)
            att_count = count_attachment(mail)
            To, From, CC, Subject, reply_to, return_path, spf, xorgip, xsenderip = extractBasicHeader(mail)
            SrcIP = getSource(mail)

            #print menu
            #To get the value at same place calculated lenth of longest string, then substracted length of current string. Added remaining value as spaces
            # ' '*2 will print spces 2 times
            # Consider example for print "\n\tSender email ID" + " "*(len("Recipient email ID(s)")-len("Sender email ID")) + " : " + From
            # Print "Sender email ID", the calculate different between longest string and current string. And print the space " "*difference
            # This will give us fixed width output

            print ("\n\tSender email ID" + " "*(len("Recipient email ID(s)")-len("Sender email ID")) + " : " + From)
            print ("\tRecipient email ID(s) : " + To)
            print ("\tCc" + " "*(len("Recipient email ID(s)")-len("Cc")) + " : " + CC)
            print ("\tSender IP / Host" + " "*(len("Recipient email ID(s)")-len("Sender IP / Host")) + " : " + str(SrcIP).replace("\n", ''))
            print ("\treply-to/return-path" + " "*(len("Recipient email ID(s)")-len("reply-to/return-path")) + " : " + reply_to + " / " + return_path)
            print ("\tSubject" + " "*(len("Recipient email ID(s)")-len("Subject")) + " : " + Subject)
            print ("\tx-org-ip/x-sender-ip" + " "*(len("Recipient email ID(s)")-len("x-org-ip/x-sender-ip")) + " : " + xorgip + " / " + xsenderip)
            print ("\tAuth-results" + " "*(len("Recipient email ID(s)")-len("Auth-results")) + " : " + spf)



            print ("\n\n\n1. Hops ")
            print ("2. Attachment(s) => ", att_count)
            print ("3. URL(s) => ", url_count)
            print ("4. Email Body")
            print ("5. Get Header")
            print ("\n--------------------------------------\n\n")
        elif opt in ['-s']:
            if arg == '2':
                extractAttachments(mail)
                print ('\n')
            elif arg == '3':
                extractURLs(mail)
                print ('\n')
            elif arg == '4':
                print('#####################################\n')
                printBody(mail)
                print('#####################################\n')
            elif arg == '1':
                printHops(mail)
            elif arg == '5':
                printHeader(mail)
            else:
                print ("\nYou missed to select correct operation for \"-s\"!!!\n")

main()
