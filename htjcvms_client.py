import httplib2
import sys
import os
from xml.dom.minidom import parse, parseString

def parseXML(path):
    doc=parse(path)
    email=doc.getElementsByTagName('system')[0].getAttribute('email')
    host=doc.getElementsByTagName('system')[0].getAttribute('host')
    return doc,email,host
'''
    apps=doc.getElementsByTagName('app')
    for app in apps:
        name=app.getElementsByTagName('name')[0].childNodes[0].data
        version=app.getElementsByTagName('version')[0].childNodes[0].data
        print name,version
'''        

def checkpatch(doc,email,host):
    apps=doc.getElementsByTagName('app')
    for app in apps:
        try:
            name=app.getElementsByTagName('name')[0].childNodes[0].data
            majorv=app.getElementsByTagName('majorv')[0].childNodes[0].data
            minorv=app.getElementsByTagName('minorv')[0].childNodes[0].data
            head,body=http.request(host+'/?func=checkpatch&name=%s&majorv=%s&minorv=%s&email=%s' %(name,majorv,minorv,email))      
        except IndexError:
            print "Found a error in appconfig.xml"
            exit(1)
        except Exception:
            print "Connect Server is fail"
            exit(1)
        print name,majorv,minorv,email
  
def main():
    try:
        doc,email,host=parseXML('appconfig.xml')
    except Exception:
        print "parse appconfig.xml fail,please check the file"
        exit(1)
    if len(sys.argv)<2:
        checkpatch(doc,email,host) #(name,version,url)
        exit(0)

http=httplib2.Http()

if __name__ == '__main__':
    main()