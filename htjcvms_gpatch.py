import httplib2
import urllib2
import os
import sys
import sqlite3
import re
from xml.dom.minidom import parse, parseString
import htjcvms_email

try:
    from bs4 import *
except Exception:
    from BeautifulSoup import *



def sqlinsert(cursor,table,values):
    vs="'"+"','".join(values)+"'"
    sql="Insert into %s values(%s)" %(table,vs)
    try:
        cursor.execute(sql)
        htjcvms_email.emailbody+=vs+'\n</br>'
    except sqlite3.IntegrityError:
        parse
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
                vid=riskcve[i*2+1].findNext()['name']
                #download new version...
                sqlinsert(cursor,'httpd',(major,mijor,fixv,vid,risk))
                if __debug__:
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
                if major=='8.0':
                    mijor=getrange4str('[\d\.(-RC)]+',mijor)
                else:
                    mijor=getrange4str('[\d\.]+',mijor)
                try:
                    if ty=='tomcatjk':
                        fixv=re.search('[\d\.]+',fix.contents[0]).group()
                    else:
                        fixv=re.search('[\d\.(\-RC)]+',fix.contents[2]).group()
                except Exception:
                    fixv=""
                risk=risks[i].contents[0][:risks[i].contents[0].index(':')]
                vid=risks[i].findNext('a').contents[0]
                sqlinsert(cursor,ty,(major,mijor,fixv,vid,risk))
                if __debug__:                
                    print major,mijor,fixv,vid,'',risk
                
def getrange4str(res,mijors):
    match=re.findall(res,mijors)
    if len(match)==2:
        return "%s:%s" %(match[0],match[1])
    if len(match)==1:
        if mijors.find('prior')>=0:
            return "<%s" %match[0]
        else:
            return match[0]
    
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

def getversion4ssl(dds):
    faff=[]
    aff=[]
    for dd in dds:
        if dd.contents[0].name:
            if aff:
                faff.append(aff)
                aff=[]
                faff
            continue
        if dd.contents[0].find('Fixed')>=0:
            aff.append(getversion4rs(dd.contents[0]))
    return faff

def getversion4rs(rs):
    fix=re.search('\d\.\d\.\d\w+',rs).group()
    mijor=rs[rs.find('(')+10:-2]
    return fix,mijor

def getpatch2openssl(cursor,url,app):
    uf=urllib2.urlopen(url)
    if uf.getcode()==200:
        soup=BeautifulSoup(uf.read())
        dls=soup.findAll('dl')
        for dl in dls:
            dds=dl.findAll('dd')
            for dd in dds:
                if (not dd.contents[0].name) and dd.contents[0].strip():
                    fix,mijor=getversion4rs(dd.contents[0])
                    sqlinsert(cursor,'openssl',('',fix,mijor,'',''))
                    if __debug__:
                        print '',fix,mijor,'',''
            '''
            dts=dl.findAll('dt')
            if len(faff)!=len(dts):
                print "have error parse %s" %url
                return
            for i in range(len(dts)):
                vid=dts[i].contents[0].a['name']
                i1=dts[i].contents[1].find('[')
                i2=dts[i].contents[1].find(']')
                if i1>=0 and i2>=0:
                    risk=dts[i].contents[1][i1+1:i2]
                else:
                    risk=""
            '''
                     
def getpatch2struts(cursor,url,app):
    http=httplib2.Http()
    head,body=http.request(url)
    if head['status']=='200':
        soup=BeautifulSoup(body)
        ul=soup.find('ul',{'class':'childpages-macro'})
        urls=ul.findAll('a',{'shape':'rect'})
        for url in urls:
            getpatch2strutsurl(cursor,"http://struts.apache.org/docs/"+url['href'],app)

def getpatch2strutsurl(cursor,url,app):
    http=httplib2.Http()
    head,body=http.request(url)
    print url
    if head['status']=='200':
        soup=BeautifulSoup(body)
        itable=soup.find('table',{'class':'confluenceTable'})
        titles=itable.findAll('th')
        values=itable.findAll('td')
        if len(titles)!=len(values):
            print "parse url %s error" %url
            return
        major='2'
        mijor=''
        risk=''
        vid=''
        fix=''
    
        for i in range(len(titles)):
            if titles[i].p.contents[0].find('rating')>=0:
                risk=values[i].p.contents[0].strip()
            if titles[i].p.contents[0].find('Recommendation')>=0:
                fix=values[i].a.contents[0]
                fix=re.search('Struts (2(\.\d{1,2})+)',fix).group(1)
            if titles[i].p.contents[0].strip().find('Affected')==0:
                affects=values[i].p.contents[0]
                rgs=re.findall('Struts (2(\.\d{1,2})+)',affects)
                if not rgs:
                    rgs=re.findall('(2(\.\d{1,2})+)',affects)
                mijor=rgs[0][0]+':'+rgs[1][0]
        sqlinsert(cursor,'struts',(major,mijor,fix,vid,risk))
        if __debug__:
            print major,mijor,fix,vid,risk
        
def getresult2db(cursor,rs,url,apps):
    for app in apps:
        if rs.find(app['match'])==0:
            if app['name']=='jdk' or app['name']=='jre':
                afdt=getversion4s(rs,app['major'],'java')
            else:
                afdt=getversion4s(rs,app['major'])
            if not afdt:
                return
            if __debug__:
                print rs
            for major,affect in afdt.iteritems():
                sqlinsert(cursor,app['name'],(major,','.join(affect),'',url))
        
def getversion4s(rs,rmajor,sp=None):
    try:
        msg,vs=rs.split(',',1)
    except ValueError:
        return
    if vs.find('version')==-1:
        return
    
    afs=[]
    afdt={}
    vs=vs.split(',')
    for v in vs:
        if sp=='java':
            vv=re.findall('\du\d+',v)
            vv=[i for i in vv if i[0]!='0']
        else:
            vv=re.findall('[\d\.]+',v)
        if len(vv)==2:
            afs.append("%s:%s" %(vv[0],vv[1]))
        if len(vv)==1:
            if v.find('earlier')>=0 or v.find('prior')>=0:
                afs.append("<=%s" %vv[0])
            else:
                afs.append(vv[0])
    if len(afs)>0:
        for af in afs:
            try:
                major=re.search(rmajor,af).group(1)
            except Exception:
                return
            if not afdt.get(major):
                afdt[major]=[af]
            else:
                afdt[major].append(af)
        return afdt
        
def getpatch2orcpurl(cursor,url,app):
    if url[-3:]=='pdf':
        return
    http=httplib2.Http()
    head,body=http.request(url)
    print url
    if head['status']=='200':
        soup=BeautifulSoup(body)
        table=soup.find('table',{'class':"dataTable3padd",'width':'98%','cellspacing':'0','cellpadding':'4'})
        if not table:
            table1=soup.find('table',{"summary":"Category I"})
            table2=soup.find('table',{"summary":"Category II"})
            table3=soup.find('table',{"summary":"Category III"})
            table4=soup.find('table',{"summary":"Category IV"})
            tables=[table1,table2,table3,table4]
        else:
            tables=[table]
            
        if not tables[0]:
            dv=soup.find('div',{'class':'orcl6w3'})
            uls=dv.findAll('ul')
            for ul in uls:
                lis=ul.findAll('li')
                try:
                    for li in lis:
                        li=html2str(li)
                    if li:
                        getresult2db(cursor,li,url,app)
                except Exception:
                    pass
            return
        
        for tb in tables:
            if not tb:
                continue
            trs=tb.findAll('tr')
            if len(tables)==1:
                trs=trs[2:]
            for tr in trs:
                rs=html2str(tr.td)
                if rs:
                    getresult2db(cursor,rs,url,app)
                

def html2str(html):
    try:
        ss=html.contents
    except Exception:
        return
    if ss[0][0]==u'\u2022':
        rs=ss[0][1:]
    else:
        rs=ss[0]
    for s in ss[1:]:
        if type(s)==type(ss[0]):
            rs+=s
            continue
        if s.name in ('em','strong'):
            rs+=s.next
    return rs.strip()

def getpatch2oracle(cursor,url,app):
    http=httplib2.Http()
    head,body=http.request(url)
    childapps=app.getElementsByTagName('app')
    apps=[]
    for childapp in childapps:
        app=dict()
        app['name']=childapp.getAttribute('name')
        app['match']=childapp.getAttribute('match')
        app['major']=childapp.getAttribute('major')
        apps.append(app)
    
    if head['status']=='200':
        soup=BeautifulSoup(body)
        target='http://www.oracle.com'+soup.find('div',{'class':'orcl6w3'}).a['href']
    head,body=http.request(target)
    if head['status']=='200':
        soup=BeautifulSoup(body)
        cputables=soup.findAll('table',{'width':'90%','cellspacing':'1','cellpadding':'5'})
        for cputable in cputables[:1]:
            cpurls=cputable.findAll('a')   
            for cpurl in cpurls:
                getpatch2orcpurl(cursor,cpurl['href'],apps)
                
def getpatch2microsoft(cursor,url,app):
    import urllib2
    import datetime
    f=urllib2.urlopen(url)
    if f.getcode()==200:
        #last=app.getElementsByTagName('date')[0].childNodes[0].data
        soup=BeautifulSoup(f.read())
        itable=soup.find('tbody',{'id':'tbodySBResults'})
        new=itable.td.contents[0].replace('/','-')
        rs=cursor.execute('select time from microsoft order by time desc').fetchall()
        if rs:
            last=rs[0][0]
            if (new-last).days>0:
                updatapage=soup.find('div',{'class':'RichText'}).li.a['href']
                sqlinsert(cursor,'microsote',('microsoft',new,updatapage))
        else:
            updatapage=soup.find('div',{'class':'RichText'}).li.a['href']
            sqlinsert(cursor,'microsoft',('microsoft',new,updatapage))
        
        if __debug__:
            print 'microsoft',new,updatapage
        #ny,nm,nd=newtime.split('\/')
        #oy,om,od=last.split('\/')
        #last=datetime.datetime(ny,nm,nd)
        #new=datetime.datetime(oy,om,od)

            #smtp=htjcvms_email.getsmtp()
            #htjcvms_email.sendemail(smtp,email,"Found a new security report in <a href='%s'>this</a></br>" %updatapage)
            
def distribute(cursor,name,url,app):
    disttable={'apache22':getpatch2apache22,'apache24':getpatch2apache24,'struts':getpatch2struts,\
               'taglib':getpatch2taglib,'tomcat5':getpatch2tomcat5,'tomcat6':getpatch2tomcat6,\
               'tomcat7':getpatch2tomcat7,'tomcat8':getpatch2tomcat8,'tomcatjk':getpatch2tomcatjk,\
               'openssl':getpatch2openssl,'oracle':getpatch2oracle,'microsoft':getpatch2microsoft}    
    if not disttable.get(name):
        print "this system have not support %s" %name
    disttable[name](cursor,url,app)
