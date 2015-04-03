import httplib2
import os
import sys
import sqlite3
try:
    from bs4 import *
except Exception:
    from BeautifulSoup import *


def initdb(name):
    conn=sqlite3.connect(name)
    cu=conn.cursor()
    cu.execute("create table httpd (majorv varchar(10),minorv char(1024),fix varchar(10),vid varchar(20),fpath varchar(128))")
    cu.execute("create table tomcat (majorv varchar(10),minorv char(1024),fix varchar(10),vid varchar(20),fpath varchar(128))")
    cu.execute("create table oracledb (majorv varchar(10),minorv char(1024),fix varchar(10),vid varchar(20),fpath varchar(128))")
    cu.execute("create table mysql (majorv varchar(10),minorv char(1024),fix varchar(10),vid varchar(20),fpath varchar(128))")
    return conn,cu
def getpatch2apache22():
    pass
def getpatch2apache24():
    pass
def getpatch2tomcat5():
    pass
def getpatch2tomcat6():
    pass
def getpatch2tomcat7():
    pass
def getpatch2tomcat8():
    pass

def getpatch2tomcatjk():
    pass
def getpatch2taglib():
    pass

def getpatch2openssl():
    pass

def getpatch2struts():
    pass

def getpatch2oracle():
    pass

def distribute(name,url):
    disttable={'apache22':getpatch2apache22}
    
