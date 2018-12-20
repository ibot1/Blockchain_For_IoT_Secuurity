import hashlib,json,requests,os,base64
import time as timer
from time import time
from urllib.parse import urlparse
from flask import Flask, flash, redirect, jsonify, request, render_template, url_for


#os.system("ulimit -Sn 1000000")
#assuming the ip-addresses will never change
def Mac_Address():
	return 'Node_5'
	
def Ip_Address():
	return 'http://10.24.7.237:8000'
	

app = Flask(__name__)
app.secret_key = Mac_Address()

class Blockchain():
	
        #fileloc='C:\\Users\\SwickZ\Desktop\\Project1\\Project1\\secureboot.txt'#for windows
        fileloc = '/home/swickz/Downloads/Project1/secureboot.txt'#for linux
        nodesIp = ['http://10.24.7.144:8000','http://10.24.4.230:8000','http://10.24.7.237:8000','http://10.24.6.109:8000']#routing table, intend on doing it automatically but it was designed for IoT
        nodesMc = ['Node_2','Node_3','Node_5','Node_4']#Mac Address table]
        verified_proof = []
        ctr = 0
        chain = {
				'chain':[{
							'node':'Root',
							'index':1,
							'timestamp':"0000000",
							"message":"genesis",
							'sechash':"safe",
							"proof":-1,
							'prev_blck_hash':"Me"
					}
				],
				'length':1
	}
        accounts = {}

        def createBlock(self,sechash,message,proof="default"):
                Block = {
					'node':Mac_Address(),
					'index':len(self.chain['chain'])+1,
					'timestamp':time(),
					'message':message,
					'sechash':sechash,
					"proof":self.hash(proof),
					'prev_blck_hash':self.hash(self.chain['chain'][-1])
		}
                return Block

        def addBlock(self,sechash,message):
                #proof = self.proof_of_work(sechash)
                node = Mac_Address()

                if(len(self.chain)==1 or self.accounts[node]["status"]=="safe"):
                        self.chain['chain'].append(self.createBlock(sechash,message))#include proof here
                        self.chain['length'] = len(self.chain['chain'])
                        return True
                return False

        def secureBoot(self):
                f = ""
                with open(self.fileloc) as file:
                        f = file.read()
                        self.ctr +=1
                return f

        def hash(self,sechash):
                sechash =  bytes(json.dumps(sechash),'utf-8')
                sechash = hashlib.sha1(base64.b64encode(sechash)).hexdigest()
                return sechash

        def ping(self, address):
                try:
                        requests.get(address+"/")
                        return True
                except Exception:
                        return False

        def validChain(self,chain):
                len1 = len(chain['chain'])
                chain = chain['chain']

                if(len1>1):
                        for i in range(1,len1):
                                if(chain[i]['prev_blck_hash'] != self.hash(chain[i-1])):	return False
                return True

        def RegisterNode(self):
                node = Mac_Address()
                x = 0
                sechash = self.secureBoot().strip(' \t\n\r')
                self.Consensus()

                if node not in self.accounts:
                        self.accounts[node] = {
							'status':"safe",
							"address":Ip_Address(),
							"service":"running",
							"time_added":time(),
							"cur_sechash":self.hash(sechash),
							"last_sec_time":time(),
							"no_of_boots":self.ctr
			}
                        print("Sucessfully Registered this Node")
                        x =1
                else:
                        if(self.hash(sechash) == self.accounts[node]["cur_sechash"] and self.accounts[node]["status"]=="safe" and self.validChain(self.chain)==True):
                                self.accounts[node]["no_of_boots"] += 1
                                self.accounts[node]["last_sec_time"] = time()
                                print("Node is Secure and Running")
                                x = 2
                        elif(self.hash(sechash) == self.accounts[node]["cur_sechash"] and self.accounts[node]["status"]!="safe" and self.validChain(self.chain)==True):
                                self.accounts[node]["status"],self.accounts[node]["no_of_boots"] = "safe",self.accounts[node]["no_of_boots"]+1
                                self.accounts[node]["last_sec_time"] = time()
                                print("Node is now Secure and Running")
                                x =3
                        else:
                                self.accounts[node]["status"],self.accounts[node]["no_of_boots"] = "unsafe",self.accounts[node]["no_of_boots"]+1
                                print(node,"isn't Secure")
                                x = 4
                        self.accounts[node]['service'] = "running"
                return x,sechash
        
        def proof_of_work(self,sechash):
                last_proof = -1
                proof = 0
                cn =0
                self.ConsensusChain(sechash)  
                while ((self.valid_proof(last_proof, proof) is False) or (proof in self.verified_proof)):
                        self.ConsensusChain(sechash) 
                        last_proof = proof
                        proof += 1
                        cn+=1
                self.verified_proof.append(proof)
                print("Proof time:",cn)
                return proof

        def valid_proof(self,last_proof, proof):
                guess = str(last_proof) + str(proof)
                guess = guess.encode()
                guess_hash = hashlib.sha256(guess).hexdigest()
                return guess_hash[:2] == "00"
			
        def Consensus(self):
                node = Mac_Address()
                len2 = len(self.nodesIp)

                for i in range(len2):
                        len1 = len(self.chain['chain'])
                        if(self.nodesIp[i]!=Ip_Address()):
                                if(self.ping(self.nodesIp[i])==True):
                                        try:
                                                chain = json.loads(requests.get(self.nodesIp[i]+"/TmpChain").text)
                                                account = json.loads(requests.get(self.nodesIp[i]+"/TmpAccount").text)
                                                proof = json.loads(requests.get(self.nodesIp[i]+"/TmpProof").text)

                                                if(self.validChain(chain)==True and account[self.nodesMc[i]]["status"]=="safe"):
                                                        self.accounts[self.nodesMc[i]] = account[self.nodesMc[i]]

                                                        if(len(chain['chain'])>len1):
                                                                self.chain = chain
                                                                self.verified_proof = proof
                                                                self.accounts[node]["no_of_boots"] += 1
                                                                print("Safe Account, Chain and Proof Updated")
                                                else:
                                                        self.accounts[self.nodesMc[i]] = account[self.nodesMc[i]]
                                                        self.accounts[self.nodesMc[i]]["status"] = "unsafe"
                                                        print("Unsafe Account: "+self.nodesMc[i])
                                        except Exception:
                                                print("Node Offline")
                                else:
                                        if(self.nodesMc[i] in self.accounts):	self.accounts[self.nodesMc[i]]["service"] = "stopped"
						

        def BlockAcceptNode(self):
                for n in self.accounts:
                        if(n!=Mac_Address()):
                                if(self.accounts[n]["status"]!="safe"):
                                        #os.system("sudo iptables -A INPUT -s "+self.accounts[n]['address'][7:16]+" -j DROP")
                                        print(n+" is malicious")
                                else:
                                        #os.system("sudo iptables -A OUTPUT -s "+self.accounts[n]['address'][7:16]+" -j ACCEPT")
                                        print(n+" isn't malicious")
        def ForceNodes(self):
                for n in self.accounts:
                        if(n!=Mac_Address()):
                                try:
                                        requests.get(self.accounts[n]["address"]+'/hold')
                                except Exception:
                                        print("Node Offline")

        def SmartContract(self):
                tmp=self.chain
                tmp1=self.accounts
                x = self.RegisterNode()
                if(x[0]==1):	self.addBlock(x[1],"Sucessfully Registered this Node")
                elif(x[0]==2):	self.addBlock(x[1],"Node is Secure and Running")
                elif(x[0]==3):	self.addBlock(x[1],"Node is now Secure and Running")
                elif(x[0]==4):	self.addBlock(x[1],"Node isn't secure")
                self.ForceNodes()
                print("Done Forcing other nodes")
                self.Consensus()
                self.BlockAcceptNode()
                self.ForceNodes()
                print("Done Forcing other nodes2")
                self.Consensus()
                
                if(len(tmp1)==len(self.accounts)):	
                        print("Your account is current")
                else:
                        print("Your account has been updated")   
		#timer.sleep(180)
		#self.SmartContract
			
			
B = Blockchain()
B.RegisterNode()

@app.route('/')
def home():
	return '''
				<head> <title> Blockchain </title> </head>
				<body>
					<h1> Welcome to my Blockchain </h1>
				</body>
	'''

@app.route('/hold')
def hold1():
    B.RegisterNode()
    return "Instructed All Active Nodes to Perform Secure Boot"
	
@app.route('/TmpChain')
def TmpChain():
	return json.dumps(B.chain)

@app.route('/chain')
def chain():
	B.SmartContract()
	return jsonify(B.chain)

@app.route('/TmpAccount')
def TmpAccount():
	return json.dumps(B.accounts)

@app.route('/account')
def account():
	B.SmartContract()
	return jsonify(B.accounts)
	
@app.route('/TmpProof')
def TmpProof():
	return json.dumps(B.verified_proof)
	
@app.route('/proof')
def proof1():
	return jsonify(B.verified_proof)	
	
if __name__ == '__main__':
	app.run(host='10.24.7.237',debug=True,port=8000)
