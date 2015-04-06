import sys
reload(sys)
sys.setdefaultencoding('gbk')
import smtplib
from email.mime.text import MIMEText
import SimpleHTTPServer
import threading
import os
import sqlite3
import time
import shutil
import htjcvms_gpatch
from xml.dom.minidom import parse, parseString

    
ppath="G:\\Pyproject\\htjcvms\\downloadfile"
smtp=None
conn=None
cu=None
status=0 #1-create init db  2-get update db
sender="yeying0311@126.com"
subject="HTJC Security Reopot:new security patch is adapt you system,please update for vulnerability system"
smtpserver='smtp.126.com'
username='htjcvms@126.com'
password='htjcvmspassword'
########################################################################
class myhttphandle(SimpleHTTPServer.SimpleHTTPRequestHandler):
    
    def do_GET(self):
        self.actfunc={'checkpatch':self.checkpatch}
        f=SimpleHTTPServer.StringIO()
        f.write('this is request args::'+self.path+'<br>')
        self.parseARGS()
        if not self.argsdit.get('func'):
            f.write('this request have not a function <br>')
            self.send_response(201,'NOTFUNC')
        if self.argsdit.get('func'):
            try:
                self.actfunc.keys().index(self.argsdit['func'])
                self.actfunc[self.argsdit['func']]()
                self.send_response(200)
            except ValueError:
                f.write('this request have a nonexist function <br>')
                self.send_response(202,'NONEXIST')
        
        length=f.tell()
        f.seek(0)        
        encoding = sys.getfilesystemencoding()
        self.send_header("Content-type", "text/html; charset=%s" % encoding)
        self.send_header("Content-Length", str(length))
        self.end_headers()
        try:
            self.copyfile(f, self.wfile)
        finally:
            f.close()
            
            
    def parseARGS(self):
        try:
            self.argsdit={}
            args=self.path[self.path.index('?')+1:]
            args=args.split('&')
            for arg in args:
                key,value=arg.split('=')
                self.argsdit[key]=value
        except Exception:
            print self.path
    
    def checkpatch(self):
        print 'this is a checkpath'
        print self.argsdit
        if status==1:
            print "server is initializing..."
        pass
    
def getsmtp():
    global smtp
    smtp=smtplib.SMTP()
    smtp.connect(smtpserver)
    smtp.login(username,password)
    
def issame(f1,f2):
    if os.path.getsize(f1)==os.path.getsize(f2):
        return 0
    if os.path.getsize(f1)>os.path.getsize(f2):
        return 1
    return -1
    
def sendemail(email,body):
    msg=MIMEText(body,'html','utf8')
    msg['Subject']=subject
    index=0
    try:
        smtp.sendmail(sender,email,msg.as_string())
    except Exception:
        if index:
            return
        getsmtp()
        smtp.sendmail(sender,email,msg.as_string())
        index+=1
        
def getdb():
    global conn
    global cu
    if os.path.isfile('htjcvms.db'):
        conn=sqlite3.connect('htjcvms.db')
        cu=conn.cursor()
        return 1
    
def closedb():
    cu.close()
    conn.close()
    
def initdb(name):
    conn=sqlite3.connect(name)
    cu=conn.cursor()
    cu.execute("create table httpd (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table tomcat (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table oracledb (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table mysql (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table tomcatjk (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table taglib (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table mysql (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table jdk (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    #return conn,cu
    #print cu.execute('select * from test').fetchall()
    conn.commit()
    cu.close()
    conn.close()
    #status=1

def checknewpatch(name):
    doc=parse('htjcvms.xml')
    #conn,cu=htjcvms_gpatch.initdb(name)
    applications=doc.getElementsByTagName('application')
    for app in applications:
        name=app.getElementsByTagName('name')[0].childNodes[0].data
        url=app.getElementsByTagName('url')[0].childNodes[0].data
        print name,url
        htjcvms_gpatch.distribute(cu,name,url,app)
    conn.commit()
    #cu.close()
    #conn.close()
    print "==========check new patch sussfully======================="

if __name__=='__main__':
    print os.getcwd()
    lastime=0
    if not getdb():
        status=1
    httpd=threading.Thread(target=SimpleHTTPServer.test,args=(myhttphandle,))
    httpd.start()
    while True:
        if status==1:
            initdb('htjcvms.db')
            getdb()
            checknewpatch('htjcvms.db')
            status=0
        time.sleep(1)#600*3)
        h=time.localtime().tm_hour
        if (h==8 or h==18) and h!=lastime or 1:
            checknewpatch('htjcvms.db')
        lastime=h
'''
            if os.path.exists('htjcvms.bk'):
                os.remove('htjcvms.bk')
            if issame('htjcvms.bk','htjcvms.db')==1:
                status=2
                closedb()
                now=time.strftime('%Y%m%d',time.localtime())
                shutil.move('htjcvms.db','databk/%s.bk' %now)
                shutil.move('htjcvms.bk','htjcvms.db')
                getdb()
                status=0
            
'''

#SimpleHTTPServer.test(myhttphandle)
#sendemail('864804336@qq.com','this is a test')
#G:\Pyproject\htjcvms