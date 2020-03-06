import threading, logging, time, queue, paramiko, argparse, re, getpass, socket
from paramiko_expect import SSHClientInteraction
#initiate parsing of command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-o', '--output', help='output log file name', required=True)
parser.add_argument('-i', '--input', help='input CSV cluster data(REQUIRED)', required=True)
args = parser.parse_args()

file = open(args.output,"w")
file.write('Host,Certificate,Expiration\n')
with open(args.input, 'r') as fd:
	data = fd.readlines()
hostList = []
for line in data:
	host1, username, password = line.split(',')
	hostList.append(host1)
	
certTypes = ['tomcat','ipsec','CallManager','CAPF','TVS']

exitFlag = 0
class myThread (threading.Thread):
	def __init__(self, threadID, name, q):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.q = q
	def run(self):
		print("Starting " + self.name)
		process_data(self.name, self.q)
		print("Exiting " + self.name)

def process_data(threadName, q):
	while not exitFlag:
		queueLock.acquire() #lock child thread and wait to receive data from parent thread
		if not workQueue.empty():
			hostAddress = q.get(host)
			u = q.get(username)
			p = q.get(password)
			p = re.sub('\n', '', p)
			p = re.sub('\r', '', p)
			print(u + ' ' + p + ' ' + hostAddress)
			queueLock.release() #release lock
			print((threadName) + ' -> processing')
			try:
				client = paramiko.SSHClient()
				client.load_system_host_keys()
				client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				client.connect(hostname=hostAddress, username=u, password=p, banner_timeout=120)
				prompt = 'admin:'
				accept = 'Continue \(y\/n\)\?'
				interact = SSHClientInteraction(client, timeout=120, display=False)
				interact.expect(prompt)
			except socket.gaierror:
				print(hostAddress + ' -> FAILED socket/dns error')
				print('Exiting ' + threadName)
				exit(1)
			print(hostAddress + ' -> SUCCESS ssh connected!')
			interact.send('set cli pagination off')
			interact.expect(prompt)
			for certType in certTypes:
				try:
					interact.send('show cert own ' + certType)
					interact.expect(prompt)
					cmd_output_pd = interact.current_output_clean
					pd = cmd_output_pd.split('\n')
					out = re.findall('(To:\s+\S+\s\S+\s+\d+\s\S+\s\S+\s\S+|Not\sAfter\s:\s+\S+\s+\d+\s\S+\s\S+\s\S+)', cmd_output_pd, re.DOTALL)[0]
					out = re.sub('(To:\s+|Not\s+After\s+:\s+)', '', out)
					print(hostAddress + ' ' + certType + ' expires ' + out)
					file.write(hostAddress + ',' + certType + ',' + out + '\n')
				except Exception:
					#interact.send('exit')
					continue
			#interact.send('exit')
		else:
			queueLock.release()
#set thread list
threadList = []
t = 1
for host2 in hostList:
	if t < 10:
		threadList.append('Thread0' + str(t) + ' -> ' + str(host2))
	else:
		threadList.append('Thread' + str(t) + ' -> ' + str(host2))
	t += 1
queueLock = threading.Lock()
workQueue = queue.Queue()
threads = []
threadID = 1
# Create new threads
for tName in threadList:
	thread = myThread(threadID, tName, workQueue)
	thread.start()
	threads.append(thread)
	threadID += 1
# Fill the queue
queueLock.acquire() #acquire the lock on thread to send data from the queue
for line in data:
	host, username, password = line.split(',')
	workQueue.put(host)
	workQueue.put(username)
	workQueue.put(password)
queueLock.release() #release the lock
# Wait for queue to empty
while not workQueue.empty():
	pass
# Notify threads it's time to exit
exitFlag = 1
# Wait for all threads to complete
for t in threads:
	t.join()
print("Exiting Main Thread")
file.close()