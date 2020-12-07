import boto3
import botocore 
import paramiko 
#import StringIO
import io



NODE_IP = ["3.12.188.219", "3.22.158.193", "3.133.229.228", "3.16.190.28"]


key = paramiko.RSAKey.from_private_key_file("OmTrial1.pem")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
def runSshCommand():
    #for i in range(len(NODE_IP)):
    for i in range(3):
        try:
            print(NODE_IP[i])
            client.connect(hostname=NODE_IP[i], username="ubuntu", pkey=key)

            #stdin, stdout, stderr = client.exec_command('uptime')
            #stdin, stdout, stderr = client.exec_command('ls -l')

            stdin, stdout, stderr = client.exec_command('cd LISS_DKG/DKG')
            command_string = "python3 bbss_node.py " + str(i)
            stdin, stdout, stderr = client.exec_command('command_string')
        except Exception as e:
            print (e) 
    print (stdout.read())
    client.close()

if __name__=="__main__":
    runSshCommand()


