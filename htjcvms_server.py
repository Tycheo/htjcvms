import sys
reload(sys)
sys.setdefaultencoding('gbk')

import SimpleHTTPServer
import threading
import os
import sqlite3
import time
import shutil
import htjcvms_gpatch
from xml.dom.minidom import parse, parseString
import htjcvms_email
    
ppath="G:\\Pyproject\\htjcvms\\downloadfile"
conn=None
cu=None
db=None 
status=0
########################################################################
class myhttphandle(SimpleHTTPServer.SimpleHTTPRequestHandler):
    
    def getcursor(self):
        if self.db:
            self.db=getdb()
            
    def do_GET(self):
        self.actfunc={'checkpatch':self.checkpatch,'listinfo':self.listinfo,'addpatch':self.addpatch}
        f=SimpleHTTPServer.StringIO()
        #self.getcursor()
        #f.write('ok<br>')#this is request args::'+self.path+'<br>')
        if not self.dbisok(f):
            return
        self.parseARGS()
        if not self.argsdit:
            fp=os.getcwd()+self.path
            if os.path.isfile(fp):
		hf=open(fp)
                f.write(hf.read())
		hf.close()
            else:
                f.write("request page is not exist</br>")
            self.senddata(f,200,'PAGE')
            return
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
	    if self.argsdit['name']=='microsoft':
		rs=db[1].execute('select * from microsoft where newdate>=%s' %self.argsdit['date'])
		urls=""
		for r in rs:
		    urls+=r[2]
		    f.write(','.join(r)+'<br>')
		if f.tell()>10:
		    if self.argsdit.get('email'):
			smtp=htjcvms_email.getsmtp()
			htjcvms_email.sendemail(smtp,self.argsdit['email'],"Found new security update for microsoft in %s" %urls)
		    self.senddata(f,211,'MSBD')
		else:
		    self.senddata(f,208,'MSOK')
		return
            rs=db[1].execute("select * from %s where major='%s'" %(self.argsdit['name'],self.argsdit['major'])).fetchall()
            for r in rs:
                if inrange(r[1],self.argsdit['mijor']):
                    f.write(','.join(r)+'<br>')
	    f.write('Best version is %s </br>' %self.selectbest(rs,self.argsdit['mijor']))
            if f.tell()>10:
		if self.argsdit.get('email'):
		    smtp=htjcvms_email.getsmtp()
		    best=self.selectbest(rs,self.argsdit['mijor'])
		    htjcvms_email.sendemail(smtp,self.argsdit['email'],"Found a Vulnerability version in %s,please update it to %s" %(self.argsdit['name'],best))
                self.senddata(f,210,'VBD')
		
            else:
                self.senddata(f,209,'VOK')
        except Exception:
            f.write('a invaild request<br>')
            self.senddata(f,203,'INVP')
	    
    def selectbest(self,rlist,fv):
	for r in rlist:
	    if inrange(r[1],fv):
		return self.selectbest(rlist,r[2])
	return fv
    
    def dbisok(self,f):
        global db       
        if status==1:
            f.write("server db is initializing,it's get data from internet<br>")
            self.senddata(f,204,'INIT')
            return
        if not db:
            db=getdb()
        return 1
    
    def listinfo(self,f):
        #listinfo name   
        try:
            rs=db[1].execute('select * from %s' %self.argsdit['name']).fetchall()
	    if len(rs[0])==5:
		f.write('<html>\n<title>%s table</title>\n<head><h1>%s infortion table</h1></head>\n' %(self.argsdit['name'],self.argsdit['name']))
		f.write("<body><table border=5><tbody>\n<tr><th>name</th><th>major</th><th>mijor</th><th>fix</th><th>vid</th><th>risk</th></tr>\n")
		for r in rs:
		    f.write("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" %(self.argsdit['name'],r[0],r[1],r[2],r[3],r[4]))
		f.write("</tbody></table></body>\n</html>")
		self.senddata(f)
		
	    if len(rs[0])==4:
		f.write('<html>\n<title>%s table</title>\n<head><h1>%s infortion table</h1></head>\n' %(self.argsdit['name'],self.argsdit['name']))
	        f.write("<body><table border=5><tbody>\n<tr><th>name</th><th>major</th><th>mijor</th><th>fix</th><th>url</th></tr>\n")
	        for r in rs:
		    f.write("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n" %(self.argsdit['name'],r[0],r[1],r[2],r[3]))
		f.write("</tbody></table></body>\n</html>")
		self.senddata(f)
		
	    if len(rs[0])==3:
		f.write('<html>\n<title>%s table</title>\n<head><h1>%s infortion table</h1></head>\n' %(self.argsdit['name'],self.argsdit['name']))
		f.write("<body><table border=5><tbody>\n<tr><th>name</th><th>time</th><th>url</th></tr>\n")
		for r in rs:
		    f.write("<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n" %(r[0],r[1],r[2]))
		f.write("</tbody></table></body>\n</html>")
		self.senddata(f)	    
        except Exception:
            f.write('A Invaild parameter<br>')
            self.senddata('203','INVP')
            
    def addpatch(self,f):
	try:
	    if self.argsdit['name'] in ('oracledb','jdk','jre','javafx','weblogic'):
		db[1].execute("insert into %s values ('%s','%s','%s','%s')" %(self.argsdit['name'],self.argsdit['major'],self.argsdit['mijor'],self.argsdit['fix'],self.argsdit['url']))
	    elif self.argsdit['name']=='microsoft':
		db[1].execute("insert into %s values ('%s','%s','%s')" %('microsoft','microsoft',self.argsdit['time'],self.argsdit['url']))
	    else:
		db[1].execute("insert into %s values ('%s','%s','%s','%s','%s')" %(self.argsdit['name'],self.argsdit['major'],self.argsdit['mijor'],self.argsdit['fix'],self.argsdit['vid'],self.argsdit['risk']))
	    
	    f.write("<h2>ADD NEW PATCH INFO SUCCFULLY</br></h2>")
	    self.senddata(f)
	except Exception:
	    f.write("<h2>ADD INFO FAILD</br><h2>")
	    self.senddata(f,205,'FAILD')
	    
    def __del__(self):
        db[0].commit()
        db[1].close()
        db[0].close()
        

            
def inrange(src,dst):
    if dst=="":
	return False
    ss=src.split(',')
    for s in ss:
        if inrge(s,dst):
            return True
    return False

def inrge(s,dst):
    s=s.strip()
    dst=dst.strip()
    if s[0]=='<':
        if s[1]=='=':
            if compares(s[2:],dst)>=0: 
                return True
        else:
            if compares(s[1:],dst)>0:
                return True
        return False
    
    rg=s.split(':')
    if len(rg)==2:
        if rg[0][-1]!='>' and rg[1][0]!='<' and compares(rg[0][:-1],dst)<=0 and compares(rg[1][1:],dst)>=0:
            return True
        if rg[0][-1]=='>' and rg[1][0]=='<' and compares(rg[0],dst)<0 and compares(rg[1],dst)>0:
            return True
        if rg[0][-1]=='>' and rg[1][0]!='<' and compares(rg[0][:-1],dst)<0 and compares(rg[1],dst)>=0:
            return True
        if rg[0][-1]!='>' and rg[1][0]=='<' and compares(rg[0],dst)<=0 and compares(rg[1][1:],dst)>0:
            return True
    else:
        if compares(s,dst)==0:
            return True
    return False

def compares(s1,s2,sp='.'):
    d1=s1.split(sp)
    d2=s2.split(sp)
    l1=len(d1)
    l2=len(d2)
    if l1>=l2:
        m=l2
    else:
        m=l1
    for i in range(m):
        try:
            i1=int(d1[i])
            i2=int(d2[i])
            if i1>i2:
                return 1
            if i1<i2:
                return -1
        except Exception:
            print "Exception in compares:",s1,s2
            return 0
    if l1==l2:
        return 0
    elif l1>l2:
        return 1
    else:
        return -1
    

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
    cu.execute("create table httpd (major varchar(10),mijor char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(major,mijor,fix,vid,risk))")
    cu.execute("create table tomcat (major varchar(10),mijor char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(major,mijor,fix,vid,risk))")
    cu.execute("create table tomcatjk (major varchar(10),mijor char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(major,mijor,fix,vid,risk))")
    cu.execute("create table taglib (major varchar(10),mijor char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(major,mijor,fix,vid,risk))")    
    cu.execute("create table mysql (major varchar(10),mijor char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(major,mijor,fix,vid,risk))")    
    cu.execute("create table struts (major varchar(10),mijor char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(major,mijor,fix,vid,risk))")
    cu.execute("create table openssl (major varchar(10),mijor char(1024),fix varchar(10),vid varchar(20),risk varchar(20),primary key(major,mijor,fix,vid,risk))")
    
    cu.execute("create table jdk (major varchar(10),mijor char(1024),fix varchar(10),url varchar(1024),primary key(major,mijor,fix,url))")
    cu.execute("create table jre (major varchar(10),mijor char(1024),fix varchar(10),url varchar(1024),primary key(major,mijor,fix,url))")
    cu.execute("create table javafx (major varchar(10),mijor char(1024),fix varchar(10),url varchar(1024),primary key(major,mijor,fix,url))")
    cu.execute("create table weblogic (major varchar(10),mijor char(1024),fix varchar(10),url varchar(1024),primary key(major,mijor,fix,url))")
    cu.execute("create table oracledb (major varchar(10),mijor char(1024),fix varchar(10),url varchar(1024),primary key(major,mijor,fix,url))")
    
    cu.execute("create table microsoft (name varchar(10),time date,url varchar(1024),primary key(name,time,url))")
    
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
    if htjcvms_email.emailbody:
	smtp=htjcvms_email.getsmtp()
	htjcvms_email.sendemail(smtp,'yeying0311@126.com',htjcvms_email.emailbody)
	htjcvms_email.emailbody=""
    print "==========check new patch sussfully======================="
    
   
if __name__=='__main__':
    print os.getcwd()
    lastime=0
    gdb=getdb()
    if not gdb:
        status=1
    httpd=threading.Thread(target=SimpleHTTPServer.test,args=(myhttphandle,))
    httpd.start()
    while True:
        if status==1:
            gdb=initdb('htjcvms.db')
            checknewpatch(gdb,'htjcvms.db')
            status=0
        time.sleep(600*3)#600*3)
        h=time.localtime().tm_hour
        if (h==8 or h==18) and h!=lastime or 1:
            checknewpatch(gdb,'htjcvms.db')
        lastime=h

#SimpleHTTPServer.test(myhttphandle)
#sendemail('864804336@qq.com','this is a test')
#G:\Pyproject\htjcvms