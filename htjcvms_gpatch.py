import httplib2
import os
import sys
import sqlite3
from xml.dom.minidom import parse, parseString
try:
    from bs4 import *
except Exception:
    from BeautifulSoup import *



def sqlinsert(cursor,table,values):
    vs="'"+"','".join(values)+"'"
    sql="Insert into %s values(%s)" %(table,vs)
    try:
        cursor.execute(sql)
    except sqlite3.IntegrityError:
        pass
    #except Exception:
    #    print sql
    
def getpatch2apache(major,cursor,url,app):
    http=httplib2.Http()
    head,body=http.request(url)
    if head['status']=='200':
        soup=BeautifulSoup(body)
        contents=soup.find('div',{'id':'apcontents'})
        fixs=contents.findAll('h1')
        for fix in fixs[1:]:
            vfix=fix.findNext('dl')
            dt=vfix.findAll('dd')
            affects=[i for i in dt if i.contents[0].find('Affects')>=0]
            riskcve=vfix.findAll('b')
            if len(affects)*2!=len(riskcve):
                print "have error in parse html %s" %url
                return
            for i in range(len(affects)):
                mijor=affects[i].contents[0][affects[i].contents[0].index(':')+1:].replace('\n','').strip()
                fixv=fix.contents[0][23:]
                risk=riskcve[i*2].contents[0]
                risk=risk[:risk.index(':')]
                vid=riskcve[i*2+1].findNext().attrs[0][1]
                #download new version...
                sqlinsert(cursor,'httpd',(major,mijor,fixv,vid,risk))
                print fixv,risk,vid,major,mijor

def clears(lists,majic):
    rs=[]
    for lt in lists:
        if lt.contents[0].find(majic)>=0:
            continue
        rs.append(lt)
    return rs

def getpatch2tomcat(major,cursor,url,app,ty='tomcat'):
    http=httplib2.Http()
    head,body=http.request(url)
    if head['status']=='200':
        soup=BeautifulSoup(body)
        contents=soup.find('div',{'id':'content'})
        fixs=contents.findAll('h3')
        for fix in fixs[2:]:
            if fix.contents[0].find('Not')==0:
                continue
            vfix=fix.findNext('div')
            risks=vfix.findAll('strong')
            risks=clears(risks,'Note')
            dt=vfix.findAll('p')
            affects=[i for i in dt if i.contents[0].find('Affects')>=0]
            if len(affects)!=len(risks):
                print "have error in paser html %s" %url
                return
            for i in range(len(affects)):
                mijor=affects[i].contents[0][affects[i].contents[0].index(':')+1:].replace('\n','').strip()
                try:
                    fixv=re.search('[\d\.(\-RC)]+',fix.contents[2]).group()
                except Exception:
                    fixv=""
                risk=risks[i].contents[0][:risks[i].contents[0].index(':')]
                vid=risks[i].findNext('a').contents[0]
                sqlinsert(cursor,ty,(major,mijor,fixv,vid,risk))
                print major,mijor,fixv,vid,'',risk
                
def getpatch2apache22(cursor,url,app):
    getpatch2apache('2.2',cursor,url,app)
def getpatch2apache24(cursor,url,app):
    getpatch2apache('2.4',cursor,url,app)
    
def getpatch2tomcat5(cursor,url,app):
    getpatch2tomcat('5.0',cursor,url,app)
def getpatch2tomcat6(cursor,url,app):
    getpatch2tomcat('6.0',cursor,url,app)
def getpatch2tomcat7(cursor,url,app):
    getpatch2tomcat('7.0',cursor,url,app)
def getpatch2tomcat8(cursor,url,app):
    getpatch2tomcat('8.0',cursor,url,app)

def getpatch2tomcatjk(cursor,url,app):
    getpatch2tomcat('1.2', cursor, url, app,'tomcatjk')
def getpatch2taglib(cursor,url,app):
    getpatch2tomcat('1.2', cursor, url, app,'taglib')

def getpatch2openssl(cursor,url,app):
    pass

def getpatch2struts(cursor,url,app):
    pass



def getresult4oracle(rs,apps):
    for app in apps:
        if rs.find(app['match'])==0:
            rs={}
            rs['name']=app['name']
            rs['values']=('major','mijor','fix','vid','risk')
            return rs
        
def getpatch2orcpurl(cursor,url,app):
    http=httplib2.Http()
    head,body=http.request(url)
    if head['status']=='200':
        soup=BeautifulSoup(body)
        table=soup.find('table',{'class':"dataTable3padd",'width':'98%','cellspacing':'0','cellpadding':'4'})
        trs=table.findAll('tr')
        for tr in trs[2:]:
            rs=tr.td.contents[0]
            rs=getresult4oracle(rs,app)
            if rs:
                sqlinsert(cursor,rs['name'],rs['values'])

def getpatch2oracle(cursor,url,app):
    http=httplib2.Http()
    head,body=http.request(url)
    childapps=app.getElementsByTagName('app')
    apps=[]
    for childapp in childapps:
        app=dict()
        app['name']=childapp.getAttribute('name')
        app['match']=childapp.getAttribute('match')
        apps.append(app)
    
    if head['status']=='200':
        soup=BeautifulSoup(body)
        target='http://www.oracle.com'+soup.find('a',{'target':''})['href']
    head,body=http.request(target)
    if head['status']=='200':
        soup=BeautifulSoup(body)
        cputables=soup.findAll('table',{'width':'90%','cellspacing':'1','cellpadding':'5'})
        for cputable in cputables[:1]:
            cpurls=cputable.findAll('a')   
            for cpurl in cpurls:
                getpatch2orcpurl(cursor,cpurl['href'],app)

def distribute(cursor,name,url,app):
    disttable={'apache22':getpatch2apache22,'apache24':getpatch2apache24,'struts':getpatch2struts,\
               'taglib':getpatch2taglib,'tomcat5':getpatch2tomcat5,'tomcat6':getpatch2tomcat6,\
               'tomcat7':getpatch2tomcat7,'tomcat8':getpatch2tomcat8,'tomcatjk':getpatch2tomcatjk,\
               'openssl':getpatch2openssl,'oracle':getpatch2oracle}    
    if not disttable.get(name):
        print "this system have not support %s" %name
    disttable[name](cursor,url,app)
