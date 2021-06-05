__author__    = "Eddy Lee"
__email__     = "yxl74@cse.psu.edu"
__copyright__ = "Copyright (C) 2020 PolyScope Project"
__license__   = "Public Domain"
__version__   = "5.0"
__date__      = "Jan 2021"

from helper import *
import operator, sys, time, os
import argparse
import threading
from ppadb.client import Client as AdbClient
from new_mac_module import MAC_TE


class Proc:
	def __init__(self):
		self.MAC_label = ""
		self.MLS = [] #Category only
		self.UID = ""
		self.GID = ""
		self.subgroup = set()
		self.PID = -1


class Obj:
	def __init__(self, m_lable, owner, group, perms, filepath):
		self.MAC_label = m_lable
		self.owner = owner
		self.group = group
		self.perm = perms
		self.path = filepath

	def __hash__(self):
		return hash(self.path)

	def __eq__(self,other):
		return self.path == other.path

	def __ne__(self,other):
		return self.path != other.path

class Integrity_Violation:
	def __init__(self, attacker_pid, victim_pid, hash_value):
		self.att = attacker_pid
		self.vic = victim_pid
		self.hash_v = hash_value

	def __hash__(self):
		return hash(self.hash_v)

	def __eq__(self, other):
		return (self.hash_v == other.hash_v)

	def __ne__(self,other):
		return (self.hash_v != other.hash_v)



class Result:
	def __init__(self):
		self.read_lock = threading.Lock()
		self.write_lock = threading.Lock()
		self.binding_lock = threading.Lock()
		self.pathname_lock = threading.Lock()
		self.result_lock = threading.Lock()

		self.read_IV = {}
		self.write_IV = {}
		self.binding_IV = {}
		self.pathname_IV = {}




class Polyscope():
	def __init__(self, device):
		self.name = device
		
		self.dir_perms = {}
		self.init_dir_perms()
		
		self.p_class = {}
		self.process_classification()


		#Get MAC info
		self.mac_analysis = MAC_TE(self.name)


		print("Parsing Process Info......")
		self.processes = {}
		self.parse_process_file()

		print("Parsing subgroup info.....")
		self.subgroup = {}
		self.init_subgroup()




	def find_id_to_name(self, Id):
		client = client = AdbClient(host="127.0.0.1", port=5037)
		devices = client.devices()
		device = devices[0]
		gname = ""
		
		def handler1(connection):
			data = connection.read_all()
			data = data.decode('utf-8')
			nonlocal gname
			gname = data.split()[0]
			connection.close()

		device.shell("su -c \"id -nu " + Id + "\"", handler = handler1)
		return gname


	#Parse Process info
	def parse_process_file(self):
		with open("./ps-Z-list/" + self.name, "r") as f:
			next(f)
			for line in f:
				new_proc = Proc()
				line_list = line.split()
				new_proc.MAC_label = line_list[0].split(":")[2]
				if len(line_list[0].split(":")) == 5:
					#MLS cat available
					mls_lst = line_list[0].split(":")[4].split(",")
					for cat in mls_lst:
						new_proc.MLS.append(cat)
				new_proc.UID = self.find_id_to_name(line_list[1])
				new_proc.GID = self.find_id_to_name(line_list[2])
				new_proc.PID = line_list[-1]
				self.processes[new_proc.PID] = new_proc

	#Dynamic: obtain subgroup name from ID #
	def init_subgroup(self):
		subgroup = {}
		all_gid = set()
		id_to_name = {}
		with open("./subgroup/" + self.name) as f:
			for line in f:
				if line.startswith("Name"):
					continue
				else:
					pid = line.split()[1]
					line_split = line[line.find("Groups:")+8:]
					if line_split != "":
						pid = line.split()[1]
						line_split = line[line.find("Groups:")+8:]
						if line_split != "":
							subgroup[pid] = set()
							for sgid in line_split.split():
								subgroup[pid].add(sgid)
								all_gid.add(sgid)

		#Transfer subgroup --> name
		for sgid in all_gid:
			if int(sgid) < 10000:
				id_to_name[sgid] = self.find_id_to_name(sgid)
		for pid in subgroup:
			if pid not in self.processes:
				continue
			for sgid in subgroup[pid]:
				if int(sgid) < 10000:
					self.processes[pid].subgroup.add(id_to_name[sgid])






	
	#Classify Process by Google's definition
	def process_classification(self):
		
		def get_ps_MAC(line):
			return line.split()[0].split(":")[2]
		

		result = {}
		result["root"] = set()
		result["system"] = set()
		result["service"] = set()
		with open("./ps-Z-list/" + self.name) as f:
			next(f)
			for line in f:
				if line.split()[1] == "root":
					result["root"].add(get_ps_MAC(line))
					#Add MAC Label
				elif line.split()[1] == "system":
					result["system"].add(get_ps_MAC(line))
				
				elif "app" in get_ps_MAC(line) and line.split()[1] != "system":
					#either plat_app, priv_app, untrusted_app
					continue
				else:
					#system_services
					result["service"].add(get_ps_MAC(line))
		
		self.p_class = result


	#Get Priv Level of Process
	def get_priv_level(self, MAC_label):
		if MAC_label in self.p_class["root"]:
			return 5
		elif MAC_label in self.p_class["system"]:
			return 4
		elif MAC_label in self.p_class["service"]:
			return 3
		else:
			if "priv_app" in MAC_label:
				return 2
			if "platform_app" in MAC_label:
				return 2
			return 1

	#Check whether its Inter-Level flow
	def check_attacker_victim_priv(self,attacker,victim):
		if (attacker in self.p_class["root"]):
				return -1
		if (attacker in self.p_class["system"]):
			if victim not in self.p_class["root"]:
				return -1
			else:
				return 9
		if (attacker in self.p_class["service"]):
			if victim in self.p_class["system"]:
				return 7
			if victim in self.p_class["root"]:
				return 8
			return -1
		if "platform_app" in attacker:
			if victim in self.p_class["system"]:
				return 5 
			if victim in self.p_class["root"]:
				return 6
			if victim in self.p_class["service"]:
				return 4
			return -1
		if "priv_app" in attacker:
			if victim in self.p_class["system"]:
				return 5 
			if victim in self.p_class["root"]:
				return 6
			if victim in self.p_class["service"]:
				return 4
		if "untrusted_app" in attacker:
			if victim in self.p_class["system"]:
				return 2 
			if victim in self.p_class["root"]:
				return 3
			if victim in self.p_class["service"]:
				return 1
			if "platform_app" or "priv_app" in victim:
				return 0
		
		return -1

	#Get directory permission
	def init_dir_perms(self):
		with open("./ls_lRZ/" + self.name, "r") as f:
			for line in f:
				if line[0] == 'd' and len(line.split()[0]) == 10:
					self.dir_perms[line.split()[4]] = line.split()[0:3]	
		self.dir_perms["/storage/emulated/0"] = ["drwxrwx---", "root", "everybody", "fuse"]
		with open("./ls_lRZ/" + self.name + "_emu", "r") as f:
			for line in f:
				if line[0] == 'd' and len(line.split()[0]) == 10:
					self.dir_perms[line.split()[4]] = line.split()[0:3]


	
	def check_file_reachability(self,pid, path):
		dirs = path.split("/")[1:-1] #eliminadef get_normal_perm(device):
		path_len = 0
		
		if(len(dirs) == 0): #root directory
			return True


		dir = ""

		while(path_len < len(dirs)):
			dir = dir + "/" + dirs[path_len]
			path_len += 1
			#Subject equals to owner
			if (self.processes[pid].UID == self.dir_perms[dir][1])  and self.dir_perms[dir][0][3] == 'x':
				continue
			#Subject equals to group
			if (self.processes[pid].GID == self.dir_perms[dir][2] or self.dir_perms[dir][2] in self.processes[pid].subgroup) and self.dir_perms[dir][0][6] == 'x':
				continue
			#Subject equals any
			elif self.dir_perms[dir][0][9] == 'x':
				continue
			#Possible bug here
			return False
			
		return True

	def check_dir_writability(self,pid, path):
		dirs = path.split("/")[1:-1] #eliminadef get_normal_perm(device):
		path_len = 0

		uid = self.processes[pid].UID
		group = self.processes[pid].GID

		if(len(dirs) == 0):
			if uid == "root":
				return True
			if group == "root":
				return True
			return False
		dir = ""
		while(path_len < len(dirs)):
			dir = dir + "/" + dirs[path_len]
			path_len += 1
			if uid == self.dir_perms[dir][1] and self.dir_perms[dir][0][2] == 'w':
				return True
			if (group == self.dir_perms[dir][2] or self.dir_perms[dir][2] in self.processes[pid].subgroup) and self.dir_perms[dir][0][5] == 'w':
				return True
			elif self.dir_perms[dir][0][8] == 'w':
				return True

		return False

	def check_dac_writable(self, pid, owner, group, perms):
		if self.processes[pid].UID == owner and perms[2] == 'w':
			return True
		if (self.processes[pid].GID == group or group in self.processes[pid].subgroup) and perms[5] == 'w':
			return True
		if perms[8] == 'w':
			return True
		return False

	def check_dac_readable(self, pid, owner, group, perms):
		if self.processes[pid].UID == owner and perms[1] == 'r':
			return True
		if (self.processes[pid].GID == group or group in self.processes[pid].subgroup) and perms[4] == 'r':
			return True
		if perms[7] == 'r':
			return True
		return False








class Run_analysis(threading.Thread):
	def __init__(self, threadID, fset, analysis_obj, result):
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.fset = fset
		self.poly = analysis_obj
		self.result = result

	def run(self):
		print("Thread", self.threadID)
		for line in self.fset:
			obj_label = get_dac_obj_label(line)
			owner = get_dac_owner(line)
			group = get_dac_group(line)
			perms = get_dac_perms(line)
			filename = get_dac_filename(line)

			if filename.startswith("/proc") or filename.startswith("/system") or filename.startswith("/dev"):
				continue
			if perms.startswith("d"):
				continue

			#File writer under DAC, contains proc PID
			file_writer = set()
			file_reader = set()
			dir_writer = set()
			
			mac_reader = set()
			file_owner = set()

			for pid in self.poly.processes:
				cur_proc = self.poly.processes[pid]
				
				if "magisk" in cur_proc.MAC_label:
					continue

				#check Dir Reachability
				c1 = self.poly.check_file_reachability(pid, filename)

				#Check MAC Writability
				c2 = (obj_label in self.poly.mac_analysis.subj_write_file[cur_proc.MAC_label])

				#Check MAC Readability
				c3 = (obj_label in self.poly.mac_analysis.subj_write_dir[cur_proc.MAC_label])

				#Check MAC Dir Writability
				c4 = (obj_label in self.poly.mac_analysis.subj_write_dir[cur_proc.MAC_label])

				#Check DAC Writability
				c5 = self.poly.check_dac_writable(pid, owner, group, perms)

				#Check DAC Readability
				c6 = self.poly.check_dac_readable(pid, owner, group, perms)

				#Check DAC Dir Writability
				c7 = self.poly.check_dir_writability(pid,filename)

				if c1 and c2 and c5:
					file_writer.add(pid)
				
				if c1 and c3 and c6:
					file_reader.add(pid)

				if c4 and c7:
					dir_writer.add(pid)

				if c2 and cur_proc.UID == owner:
					file_owner.add(pid)

				if c3:
					mac_reader.add(pid)


				for v_pid in file_reader:
					if "untrusted" in self.poly.processes[v_pid].MAC_label:
						continue
					for a_pid in file_writer:

						attacker_proc = self.poly.processes[a_pid]
						victim_proc = self.poly.processes[v_pid]

						#If attacker is in victim's TCB continue, not an IV
						if attacker_proc.MAC_label in self.poly.mac_analysis.integrity_wall[victim_proc.MAC_label] or \
							attacker_proc.MAC_label in self.poly.mac_analysis.TCB:
							continue


						cross_priv = self.poly.check_attacker_victim_priv(attacker_proc.MAC_label, victim_proc.MAC_label)

						#Not inter-level or Attacker more privilege than victim
						if cross_priv == -1:
							continue

						#Found Integrity Violation, Need to classify
						obj = Obj(obj_label, owner, group, perms, filename)
						hash_value = attacker_proc.MAC_label + attacker_proc.UID + attacker_proc.GID + victim_proc.MAC_label + victim_proc.UID + victim_proc.GID
						iv = Integrity_Violation(a_pid, v_pid, hash_value)




						#Write-IV
						if v_pid in file_writer:
							#victim can also write

							#critical section
							self.result.write_lock.acquire()
							
							if obj not in self.result.write_IV:
								self.result.write_IV[obj] = set()
							self.result.write_IV[obj].add(iv)

							self.result.write_lock.release()

						
						#Binding-IV
						if a_pid in dir_writer:

							#critical section
							self.result.binding_lock.acquire()

							if obj not in self.result.binding_IV:
								self.result.binding_IV[obj] = set()
							self.result.binding_IV[obj].add(iv)

							self.result.binding_lock.release()

						
						#Read-IV
							self.result.read_lock.acquire()

							if obj not in self.result.read_IV:
								self.result.read_IV[obj] = set()
							self.result.read_IV[obj].add(iv)

							self.result.read_lock.release()

				#DAC-Expansion
				for v_pid in mac_reader:
					for a_pid in file_owner:
						

						
						attacker_proc = self.poly.processes[a_pid]
						victim_proc = self.poly.processes[v_pid]

						#If attacker is in victim's TCB continue, not an IV
						if attacker_proc.MAC_label in self.poly.mac_analysis.integrity_wall[victim_proc.MAC_label] or \
							attacker_proc.MAC_label in self.poly.mac_analysis.TCB:
							continue
						
						cross_priv = self.poly.check_attacker_victim_priv(attacker_proc.MAC_label, victim_proc.MAC_label)
						
						if cross_priv == -1:
							continue


						#Found possible Pathname-IV (DAC-Expansion)
						obj = Obj(obj_label, owner, group, perms, filename)
						hash_value = attacker_proc.MAC_label + attacker_proc.UID + attacker_proc.GID + victim_proc.MAC_label + victim_proc.UID + victim_proc.GID
						iv = Integrity_Violation(a_pid, v_pid,hash_value)

						
						self.result.pathname_lock.acquire()

						if obj not in self.result.pathname_IV:
							self.result.pathname_IV[obj] = set()
						self.result.pathname_IV[obj].add(iv)

						self.result.pathname_lock.release()


def write_result(result, poly, name):
	if not os.path.isdir("./dac_result/" + name):
		os.mkdir("./dac_result/" + name)

	read_iv_f = open("./dac_result/" + name + "/read_IV", "w")
	write_iv_f = open("./dac_result/" + name + "/write_IV", "w")
	binding_iv_f = open("./dac_result/" + name + "/binding_IV", "w")
	pathname_iv_f = open("./dac_result/" + name + "/pathname_IV", "w")


	for obj in result.read_IV:
		read_iv_f.write("***" + obj.path + "***" + obj.owner + " " + obj.group + " " + obj.perm + "\n")
		for iv in result.read_IV[obj]:
			att = poly.processes[iv.att]
			vic = poly.processes[iv.vic]
			read_iv_f.write("   "+ att.MAC_label + " " + att.UID + " " + att.GID + "***" + vic.MAC_label + " " + vic.UID + " " + vic.GID + "\n")


	for obj in result.write_IV:
		write_iv_f.write("***" + obj.path + "***" + obj.owner + " " + obj.group + " " + obj.perm + "\n")
		for iv in result.write_IV[obj]:
			att = poly.processes[iv.att]
			vic = poly.processes[iv.vic]
			write_iv_f.write("   "+ att.MAC_label + " " + att.UID + " " + att.GID + "***" + vic.MAC_label + " " + vic.UID + " " + vic.GID + "\n")

	for obj in result.binding_IV:
		binding_iv_f.write("***" + obj.path + "***" + obj.owner + " " + obj.group + " " + obj.perm + "\n")
		for iv in result.binding_IV[obj]:
			att = poly.processes[iv.att]
			vic = poly.processes[iv.vic]
			binding_iv_f.write("   "+ att.MAC_label + " " + att.UID + " " + att.GID + "***" + vic.MAC_label + " " + vic.UID + " " + vic.GID + "\n")

	for obj in result.pathname_IV:
		pathname_iv_f.write("***" + obj.path + "***" + obj.owner + " " + obj.group + " " + obj.perm + "\n")
		for iv in result.pathname_IV[obj]:
			att = poly.processes[iv.att]
			vic = poly.processes[iv.vic]
			pathname_iv_f.write("   "+ att.MAC_label + " " + att.UID + " " + att.GID + "***" + vic.MAC_label + " " + vic.UID + " " + vic.GID + "\n")


if __name__ == "__main__":
	start_time = time.time()

	parser = argparse.ArgumentParser()
	parser.add_argument("-n", "--name", dest = "name", default = None,
						help = "Specify device name")
	
	parser.add_argument("-p", "--proc", dest = "proc", default = None, 
						help = "Number of Process")
	
	args = parser.parse_args()
	p_count = int(args.proc)
	polyscope = Polyscope(args.name)
	result = Result()

	ftotal = []
	fset_map = {}
	with open("./ls_lRZ/" + args.name, "r") as f:
		for line in f:
			ftotal.append(line)
	#Need to add external storage related stuff


	split = len(ftotal)//p_count + 1
	i = 0
	k = 0
	for line in ftotal:
		if i == 0:
			fset_map[k] = []
		if i < split:
			fset_map[k].append(line)
			i += 1
		if i == split:
			i = 0
			k += 1

	print("Starting Worker Thread")
	thread_pool = []
	for m in range(p_count):
		t = Run_analysis(m, fset_map[m] , polyscope, result)
		thread_pool.append(t)
		t.start()
	for trd in thread_pool:
		trd.join()

	
	print("Analysis Complete, data ouput")
	#Should have result now
	write_result(result, polyscope, args.name)
	











				







