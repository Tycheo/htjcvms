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
status=0
sender="yeying0311@126.com"
subject="HTJC Security Reopot:new security patch is adapt you system,please update for vulnerability system"
smtpserver='smtp.126.com'
username='htjcvms@126.com'
password='htjcvmspassword'
########################################################################
class myhttphandle(SimpleHTTPServer.SimpleHTTPRequestHandler):
    
    def getcursor(self):
        if self.db:
            self.db=getdb()
            
    def do_GET(self):
        if not self.dbisok(f):
            return        
        self.actfunc={'checkpatch':self.checkpatch,'listinfo':self.listinfo}
        f=SimpleHTTPServer.StringIO()
        #self.getcursor()
        f.write('ok<br>')#this is request args::'+self.path+'<br>')
        self.parseARGS()
        if not self.argsdit.get('func'):
            f.write('this request have not a function <br>')
            self.senddata(f,201,'NOTFUNC')
            return
        if self.actfunc.get(self.argsdit['func']):
            self.actfunc[self.argsdit['func']](f)
        else:
            f.write('this request have a nonexist function <br>')
            self.senddata(f,202,'NOTEXIST')
    
            
    def senddata(self,f,code=200,msg='OK'):
        length=f.tell()
        f.seek(0)
        self.send_response(code,msg)
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
    
    def checkpatch(self,f):
        #checkpatch major mijor name
        try:
            rs=db[1].execute("select * from %s where major='%s'" %(self.argsdit['name'],self.argsdit['major']))
            for r in rs:
                if inrange(r[2],self.argsdit['mijor']):
                    f.write(','.join(r))
            if f.tell()>10:
                self.senddata(f,210,'VBD')
            else:
                self.senddata(f,209,'VOK')
        except Exception:
            f.write('a invaild request<br>')
            self.senddata(f,203,'INVP')

    def dbisok(self,f):
        if status==1:
            f.write("server db is initializing,it's get data from internet")
            self.senddata(f,204,'INIT')
            return
        return 1
    def listinfo(self,f):
        #listinfo name   
        try:
            rs=db[1].execute('select * from %s' %self.argsdit['name']).fetchall()
            f.write('<html>\n<title>%s table</title>\n<head><h1>%s infortion table</h1></head>\n' %(self.argsdit['name'],self.argsdit['name']))
            f.write("<body><table border=5><tbody>\n<tr><th>name</th><th>major</th><th>mijor</mijor><th>fix</th><th>vid</th><th>risk</th></tr>\n")
            for r in rs:
                f.write("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" %(self.argsdit['name'],r[0],r[1],r[2],r[3],r[4]))
            f.write("</tbody></table></body>\n</html>")
            self.senddata(f)
        except Exception:
            f.write('A Invaild parameter<br>')
            self.senddata('203','INVP')
    def __del__(self):
        db[0].commit()
        db[1].close()
        db[0].close()
        
def getsmtp():
    global smtp
    smtp=smtplib.SMTP()
    smtp.connect(smtpserver)
    smtp.login(username,password)
    
            
def inrange(src,dst):
    ss=src.split(',')
    for s in ss:
        if inrge(s,dst):
            return True
    return False

def inrge(s,dst):
    if s[0]=='-':
        ds=s[1:].split('.')
        dt=s.split('.')
        a=len(dt)
        b=len(ds)
        if a>=b:
            m=b
        else:
            m=a
        for i in range(m):
            if int(ds[i])>int(dt[i]):
                return True
        if a>=b:
            return True
        
        return False

    
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
    if os.path.isfile('htjcvms.db'):
        conn=sqlite3.connect('htjcvms.db')
        cu=conn.cursor()
        return conn,cu
    
def closedb(cu,conn):
    conn.commit()
    cu.close()
    conn.close()
    
def initdb(name):
    conn=sqlite3.connect(name)
    cu=conn.cursor()
    cu.execute("create table httpd (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table tomcat (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table tomcatjk (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table taglib (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")    
    cu.execute("create table oracledb (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table mysql (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")    
    cu.execute("create table jdk (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table jre (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table javafx (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table weblogic (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table struts (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    cu.execute("create table openssl (majorv varchar(10),mijorv char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(majorv,mijorv,fix,vid,risk))")
    conn.commit()
    return conn,cu

def checknewpatch(db,name):
    doc=parse('htjcvms.xml')
    applications=doc.getElementsByTagName('application')
    for app in applications:
        name=app.getElementsByTagName('name')[0].childNodes[0].data
        url=app.getElementsByTagName('url')[0].childNodes[0].data
        print name,url
        htjcvms_gpatch.distribute(db[1],name,url,app)
    db[0].commit()
    print "==========check new patch sussfully======================="
    
db=None        
def theadhttp(requesthandle):
    global db
    db=getdb()
    SimpleHTTPServer.test(requesthandle)
    
if __name__=='__main__':
    print os.getcwd()
    lastime=0
    gdb=getdb()
    if not gdb:
        status=1
    #httpd=threading.Thread(target=SimpleHTTPServer.test,args=(myhttphandle,))
    httpd=threading.Thread(target=theadhttp,args=(myhttphandle,))
    httpd.start()
    while True:
        if status==1:
            gdb=initdb('htjcvms.db')
            checknewpatch(gdb,'htjcvms.db')
            status=0
        time.sleep(600)#600*3)
        h=time.localtime().tm_hour
        if (h==8 or h==18) and h!=lastime or 1:
            checknewpatch(gdb,'htjcvms.db')
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