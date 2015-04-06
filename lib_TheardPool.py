import threading
import sys
import time
import Queue
import httplib2
#=============================================================================
class threadtask(threading.Thread): #The timer class is derived from the class threading.Thread  
    def __init__(self):  
        threading.Thread.__init__(self)  
        self.flag="mypool_task"
        self.func=None
        self.args=None
    def settask(self,func,args):
        self.func=func
        self.args=args
   
    def run(self): #Overwrite run() method, put what you want the thread do here  
        self.func(*self.args)
            
########################################################################
class threadpool(threading.Thread):

    #----------------------------------------------------------------------
    def __init__(self,tmax=20,invrt=1,overact=None,start=True,tasks=0,debug=0,ishttp=False):#,taskclass=threadtask):
        threading.Thread.__init__(self)
        self.queue=Queue.Queue()
        self.threads=[None]*tmax
        #self.threads=[taskclass()]*tmax
        self.tmax=tmax
        self.invrt=invrt
        self.tasks=tasks
        self.currentasks=0
        self.overact=overact
        self.debug=debug
        self.stop=False
        self.ishttp=ishttp
        self.limit=0
        self.wait=False
        if self.ishttp:
            self.https=[httplib2.Http(timeout=10) for i in range(self.tmax)]
        if start:
            self.start()

    def run(self):
        while True:
            try:
                if self.tasks>0 and self.currentasks>=self.tasks:
                    print "\nspecify task number is complete!!!"
                    break
                if self.stop:
                    break
                func,args=self.queue.get(timeout=3)
                slot=self.getthreadslot()
                self.starttask(slot,func,args)
                self.currentasks+=1
                if self.debug:
                    print self.currentasks
            except Queue.Empty:
                print "\nThread Pool is empty"
                break
        print "Wait all subthread complete..."
        self.waitcomplete()
        if self.overact:
            self.overact[0](self.overact[1])
            #exit(0)
        print "This Progame is over sussfully!!!"
        self.stop=True
        
    def getthreadslot(self):
        while True:
            for i in range(self.tmax):
                if not isinstance(self.threads[i],threading.Thread):
                    return i
                if not self.threads[i].isAlive():
                    return i
            time.sleep(self.invrt)
            
    def starttask(self,slot,func,args):
        #self.threads[slot].settask(func,args)
        #self.threads[slot].start()
        #====================
        if self.ishttp:
            tmp=list(args)
            tmp.append(self.https[slot])
            self.threads[slot]=threading.Thread(target=func,args=tuple(tmp))
        else:
            self.threads[slot]=threading.Thread(target=func,args=args)
        self.threads[slot].start()
        if self.debug:
            print '=',self.threads[slot].getName()
            
    def addtask(self,func,args):
        self.queue.put((func,args))
    
    def waitcomplete(self):
        for t in self.threads:
            if isinstance(t,threading.Thread) and t.isAlive():
                self.wait=True
                t.join()
    def waitPoolComplete(self):
        while not self.stop:
            time.sleep(1)
            if self.wait:
                self.limit+=1
                print 'wait',self.limit
            if self.limit>100:
                break
########################################################################


  
                    
        
                
            
                
        
        
        
        
        
    
    