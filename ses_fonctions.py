import os
import sys
import socket
import sqlite3
import importlib
import subprocess
import ipaddress
from nmap import nmap
from colorama import init , Fore 

init(autoreset=True)
#import fonction_inter

version='0.0.1'

#   ma base de donneé
mydb=sqlite3.Connection('exploits.db')

""" la class use """
class use():
    def __init__(self,exploit,mode='1',**argv):
        exploit=str(exploit)
        trouve=0

        if 'CVE' not in exploit:
            exploit=exploit.lower()
        
        x=mydb.cursor()
        x.execute("SELECT * FROM EXPLOITS WHERE CVE == '{0}' OR NUM == '{0}' OR CHEMIN == '{0}' ;".format(exploit))
        for (NUM,CHEMIN, CAUSE ,CVE, SERVICE, TYPE , DESC, PORTER, OS ) in x:
            try:
                if int(NUM) == int(exploit):
                    exploit=CVE
                    trouve=1
            except:
                pass
            if exploit == CVE:
                exploit=CVE
                trouve=1
            if exploit == CHEMIN:
                exploit=CVE
                trouve=1
            if exploit == NUM:
                exploit=CVE
                trouve=1
            self.DESC=DESC
        
        if trouve == 0:
            raise Exception("Nous ne poussedons pas l\'exploit que vous cherchez ")
        
        self.exploit=exploit

        x.execute("SELECT * FROM EXPLOITS_OPTIONS WHERE CVE == '{0}';".format(exploit))
        for (CVE,RHOST,RPORT,CODE,OS,LHOST,LPORT,USER,PASSWD,USER_FILE,FILE_PASSWD) in x:
            if CVE == exploit:

                if RHOST == 'False':
                    pass
                else:
                    self.RHOST=RHOST

                if RPORT == 'False':
                    pass
                else:
                    self.RPORT= RPORT
                
                if CODE == 'False':
                    pass
                else:
                    self.PAYLOAD= str(CODE).format(self.RHOST,self.RPORT)
                
                if OS == 'False':
                    pass
                else:
                    self.OS=OS
                
                if LHOST == 'False':
                    pass
                else:
                    self.LHOST= LHOST

                if LPORT =='False':
                    pass
                else:
                    self.LPORT= LPORT

                if USER == 'False':
                    pass
                else:
                    self.USER= USER

                if PASSWD == 'False':
                    pass
                else:
                    self.PASSWD= PASSWD
                
                if USER_FILE == 'False':
                    pass
                else:
                    self.FILE_USER= USER_FILE

                if FILE_PASSWD == 'False':
                    pass
                else:
                    self.FILE_PASSWD= FILE_PASSWD
        self.exploit=exploit.replace("-","_")

        x=['show','info','options','exploit','run','DESC']

        for i in argv:
            self.__setattr__(i,str(argv[str(i)]))

    def __str__(self):
        return 'Ceci est une instance de la class use ayant pour exploit {}'.format(str(self.exploit))

    def options(self):
        print('\n')
        mod=importlib.import_module('exploits.'+self.exploit.replace('-','_'),package='exploits')
        mod.notice()
        x=['show','info','options','exploit','run','DESC']        
        for i in dir(self):
            if '__'  not in str(i) and str(i) not in x: 
                print(i+" : "+str(self.__getattribute__(i)))

    def run(self):
        mod=importlib.import_module('exploits.'+self.exploit.replace('-','_'),package='exploits')
        try:
            os.system('clear')
            mod.exploit(self)
        except KeyboardInterrupt:
            print("Fin de la session")
        
        
    def info(self):
        print(self.DESC)


# Fonction de recherche d'exploit
def search(exp):
    l,L=os.get_terminal_size()
    if l <= 70:
        print(Fore.RED +"[~] La largueur de votre terminal doit etre superieur à 70 ")
        return
    if L <= 10:
        print(Fore.RED +"[~] La longueur de votre terminal doit etre superieur à 10 ")
        return

    print('_'*l)
    print("""|Num|     CVE      |{0}Description{0}| Porter |""".format(' '*int(((l-41)/2))))
    print('_'*(l-1))
    x=mydb.cursor()
    x.execute("SELECT * FROM EXPLOITS WHERE CVE LIKE '%{0}%' OR NUM LIKE '%{0}%' OR CHEMIN LIKE '%{0}%' ;".format(exp))

    for (NUM,CHEMIN,CAUSE ,CVE, SERVICE, TYPE ,DESC, PORTER, OS ) in x:
        n_num=0
        n_cve=0
        n_desc=0
        n_porter=0
        while str(NUM)[n_num:(n_num+1)] != '' or str(CVE)[n_cve:(n_cve+14)] != '' or str(DESC)[n_desc:n_desc+(l-30)] != '':

            c_num=str(NUM)[n_num:n_num+1]
            if len(c_num) != 1:
                c_num=c_num+(' '*1)
            
            c_cve=str(CVE)[n_cve:n_cve+14]
            if len(c_cve) != 14 and len(c_cve) != 0:
                c_cve=str(CVE)[n_cve:n_cve+14]+(' '*(14-len(c_cve)))
            elif len(c_cve) == 0:
                c_cve=str(' ')*14

            c_desc=str(DESC)[n_desc:n_desc+(l-30)]
            if len(c_desc) != l-30:
                c_desc=c_desc+(' '*(41-len(c_desc)))

            c_porter=str(PORTER)[n_porter:n_porter+50]
            if len(c_porter) != 8:
                c_porter=c_porter+(' '*(8-len(c_porter)))
            print("""| {0} |{1}|{2}|{3}|""".format(c_num ,c_cve ,c_desc,c_porter))   #,str(PORTER)[n_porter:str(n_porter+56)] ) )
            n_porter=50
            n_num+=2
            n_cve+=15
            n_desc+=l-30
        print("""|   |              |{0}           {0}|        |""".format(' '*int(((l-41)/2))))

# Fonction de scannage de vulnerab pour le service en ligne
class scan_vuln():
    def __init__(self,RHOST,**argv):
        try:
            self.RHOST=socket.gethostbyname(RHOST)
        except:
            raise Exception(Fore.RED + "Echec lors de la resolution du nom de domaine")
        
        x=os.system('ping -c 1 {}'.format(self.RHOST))
        os.system('clear')
        RHOST=socket.gethostbyname(RHOST)
        islocalemachine=0

        var=['CVE','RPORT','TIMEOUT','USER_FILE','USER','PASSWD','PASSWD_FILE','PAYLOAD','LPORT']

        for i in var:
            try:
                self.__setattr__(i,argv.__getitem__(i))
            except :
                pass
        
        try:
            self.RPORT
        except AttributeError:
            self.RPORT=(0,65535)
        
        inst=nmap.PortScanner()
        P_S={}

        if x != 0:
            raise Exception(Fore.RED + "Impossible de contacter l'addresse : {}".format(self.RHOST))
        
        try:
            # support les donnée dans l'ordre [0,4,54,1]
            if type(self.RPORT) == type(list()):
                self.nCVE=2
                for i in self.RPORT:
                    try:
                        inst.scan(hosts=self.RHOST,ports=i,arguments='-A')
                        i=int(i)
                        if inst._scan_result['scan'][self.RHOST]['tcp'][i]['state'] == 'open':
                            P_S[int(i)]={'service':str(inst._scan_result['scan'][self.RHOST]['tcp'][i]['name']) ,str(inst._scan_result['scan'][self.RHOST]['tcp'][i]['product']) : str(inst._scan_result['scan'][self.RHOST]['tcp'][i]['version'])}
                    except :
                        pass
            
            # selon l'intervalle
            if type(self.RPORT) == type(tuple()):
                if len(self.RPORT) != 2:
                    raise Exception(Fore.RED + "Cette Structure n'est pas supporter \nVous devez utlilizer la Structure suivante \nx=scan_vuln_r('exemple.com',RPORT=(0,65535))")
                start,end= self.RPORT
                inst.scan(hosts=self.RHOST,ports='{}-{}'.format(start,end),arguments='-A')
                for i in range(start,end):                    
                    try:
                        if inst._scan_result['scan'][self.RHOST]['tcp'][i]['state'] == 'open':
                            service=str(inst._scan_result['scan'][self.RHOST]['tcp'][i]['name'])
                            produit=str(inst._scan_result['scan'][self.RHOST]['tcp'][i]['product'])
                            P_S[int(i)]={'service':service,'produit':produit,'version':str(inst._scan_result['scan'][self.RHOST]['tcp'][i]['version'])}
                    except:
                        pass

            # seulement le port specifié
            if type(str()) == type(self.RPORT) or type(int()) == type(self.RPORT):
                try:
                    inst.scan(hosts=self.RHOST,ports=str(self.RPORT),arguments='-A')
                    service=str(inst._scan_result['scan'][self.RHOST]['tcp'][int(self.RPORT)]['name'])
                    produit=str(inst._scan_result['scan'][self.RHOST]['tcp'][int(self.RPORT)]['product'])
                    P_S[int(self.RPORT)]={'service':service,'produit':produit,'version':str(inst._scan_result['scan'][self.RHOST]['tcp'][i]['version'])}
                    self.nCVE=1
                except IndentationError:
                    pass

        except KeyboardInterrupt:
            pass
        
        if ipaddress.IPv4Address(RHOST).is_loopback:
            self.islocalemachine=1

        self.RPORT=P_S

    def __str__(self):
        return "Ceci est une instance de la class scan_vuln aynt pour cible {} ".format(self.RHOST)
 
    def start(self):
        def tri(param): # s'occupe de rendre les parametre
            for (CVE,RHOST,RPORT,CODE,OS,LHOST,LPORT,USER,PASSWD,USER_FILE,PASSWD_FILE) in param:
                if CODE == 'False':
                    pass
                else:
                    self.PAYLOAD=CODE
                    self.PAYLOAD=self.PAYLOAD.replace('{LHOST}',self.LHOST)
                    self.PAYLOAD=self.PAYLOAD.replace('{LPORT}',self.LPORT)

                if LHOST == 'False':
                    pass
                else:
                    try:
                        self.LHOST=self.LHOST
                    except:
                        self.LHOST=LHOST

                if LPORT =='False':
                    pass
                else:
                    try:
                        self.LPORT=LPORT
                    except:
                        self.LPORT=4444

                if USER == 'False':
                    pass
                else:
                    try:
                        self.USER=self.USER
                    except:
                        self.USER=USER

                if PASSWD == 'False':
                    pass
                else:
                    try:
                        self.PASSWD=self.PASSWD
                    except:
                        self.PASSWD=PASSWD
                    
                if USER_FILE == 'False':
                    pass
                else:
                    try:
                        self.USER_FILE=self.USER_FILE
                    except:
                        self.USER_FILE=USER_FILE

                if PASSWD_FILE == 'False':
                    pass
                else:
                    try:
                        self.PASSWD_FILE=self.PASSWD_FILE
                    except:
                        self.PASSWD_FILE=self.PASSWD_FILE
        
        def tri2(param): # s'occupe de rendre les parametre
            for (CVE,RHOST,RPORT,CODE,OS,LHOST,LPORT,USER,PASSWD,USER_FILE,PASSWD_FILE) in param:
                self.RPORT=RPORT
                self.PAYLOAD=CODE
                self.USER=USER
                self.USER_FILE=USER_FILE
                self.PASSWD=PASSWD
                self.PASSWD_FILE=PASSWD_FILE

        def tri3(param):
            param=str(param)
            param=param[2:len(param)]
            param=param[0:len(param)-3]
            return param

        vulnerabilities=[]
        x=mydb.cursor()
        try:
            if type(self.CVE) == type(list()): # en cas de
                try:
                    # verifie l'existance des exploits
                    for i in self.CVE:
                        try:
                            x.execute("SELECT * FROM EXPLOITS_OPTIONS WHERE CVE == '{}';".format(i))
                            tri(x)
                        except:
                            raise Exception(Fore.RED + "Nous ne sommes pas en possessions du CVE {}".format(i))

                        mod=importlib.import_module(str(i).replace('-','_'),package='exploits')
                        x.execute("SELECT SERVICE FROM EXPLOITS_OPTIONS WHERE CVE = '{}' ;".format(self.CVE))
                        for y in self.RPORT:
                            for o in x:
                                o=tri3(o)
                                if str(self.RPORT[int(y)]['service']).lower() in str(o).lower() :
                                    vulnerabilities.append(mod.detect(self,RPORT=y))
                                else:
                                    pass
                except:
                    raise Exception()

            elif type(self.CVE) == type(str()):
                try:
                    x.execute("SELECT * FROM EXPLOITS_EXPLOITS WHERE CVE = '{}';".format(self.CVE))
                    tri2(x)
                except:
                    raise Exception(Fore.RED + "Nous ne possedons pas le CVE : {}".format(self.CVE))
                x.execute("SELECT SERVICE FROM EXPLOITS WHERE CVE = '{}' AND CHEMIN != 'locale';".format(self.CVE))
                for y in self.RPORT:
                    for o in x:
                        o=tri3(o)
                        if str(self.RPORT[int(y)]['service']).lower() in str(o).lower() :
                            mod=importlib.import_module('exploits.'+self.CVE.replace('-','_'),package='exploits')
                            vulnerabilities.append(mod.detect(self,RPORT=y))
            else:
                raise Exception( Fore.RED +'Le type de donnée que vous avez founi ne pas prevu')
        except:
            for i in self.RPORT:
                y=x.execute("SELECT CVE FROM EXPLOITS WHERE SERVICE LIKE '%{0}%' AND CHEMIN != 'locale';".format(self.RPORT[i]['service']))
                for o in y:
                    mod=importlib.import_module('exploits.'+str(tri3(o)).replace('-','_'),package='exploits')
                    x.execute("SELECT * FROM EXPLOITS_OPTIONS WHERE CVE = '{}';".format(tri3(o)))
                    tri2(x)
                    vulnerabilities.append(mod.detect(self,i))

        if self.islocalemachine == 1:
            y=x.execute("SELECT CVE FROM EXPLOITS WHERE CHEMIN != 'locale';")
            for i in y:
                i=tri3(i)
                x.execute("SELECT * FROM EXPLOITS_OPTIONS WHERE CVE = '{}' ;".format(i))
                tri2(x)
                mod=importlib.import_module('exploits.'+i.replace('-','_'),package='exploits')
                vulnerabilities.append(mod.detect())

        self.vuln=vulnerabilities

x=scan_vuln('localhost')
x.start()
print(x.vuln)