import smtplib
from email.mime.text import MIMEText

sender="htjcvms@test.com"
subject="HTJC Security Reopot:new security patch is adapt you system,please update for vulnerability system"
smtpserver='smtp.test.com'
username='htjcvms@test.com'
password='testpasswd'#htjcvmspassword'
smtp=None
emailbody=""

def getsmtp():
    #global smtp
    hemail=smtplib.SMTP()
    hemail.connect(smtpserver)
    hemail.login(username,password)
    return hemail

def sendemail(smtp,email,body):
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
        
        
if __name__=="__main__":
    getsmtp()
