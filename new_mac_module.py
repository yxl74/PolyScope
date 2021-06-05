from helper import *
import operator, sys, time
import argparse
from multiprocessing import *

class MAC_TE:

	def __init__(self, device):
		
		#Constants
		self.name = device
		self.known_HI_Objs = {"sepolicy_file", "selinuxfs", "sysfs", "rootfs", "keystore_data_file", "keychain_data_file", "system_file", "backup_data_file"}
		
		#Place holder for maps
		#TCB across the system
		self.TCB = set()
		#subj --> ececutable writer
		self.integrity_wall = {}
		#Hash maps for subj permission
		#Permission needed as attacker
		self.subj_write_file = {}
		self.subj_write_dir = {}
		
		#Permission needed as victim
		self.subj_read_file = {}
		self.subj_read_dir = {}
		self.subj_exec_file = {}
		

		#Func:init attributes, mlstrustedsubject, mlstrustedobject
		self.attr_map = {}
		self.init_attribute()
		

		#Func: Consturct system TCB, and per-subject integrity wall
		self.calc_system_TCB()
		self.construct_int_wall()


		#Map MAC data into 5 maps
		self.construct_subj_permissions()






	#Read in Attributes
	def init_attribute(self):
		with open("./attribute_file/" + self.name) as f:
			next(f)
			cur_attri = ""
			for line in f:
				if "magisk" in line:
					continue
				if ";" in line:
					cur_attri = line.split()[1].split(";")[0]
					self.attr_map[cur_attri] = set()
				else:
					#remember to check for empty attribute
					lab = line.split("\n")[0].split()[0]
					if "empty attribute" in line:
						self.attr_map.pop(cur_attri)
					else:
						self.attr_map[cur_attri].add(lab)
	
	#Calc system TCB
	def calc_system_TCB(self):


		print("Calculating system TCB............")
		kernel_subject = set() #Kernel Object Writer
		kexec_writer = set() #Kernel subject's executable writer
		path = "./mac_policy/" + self.name
		with open(path, 'r') as f:
			for line in f:
				if "magisk" in line:
					continue
				if line.startswith('allow '):
					obj = line.split()[2].split(':')[0]
					if obj in self.known_HI_Objs or "kernel" in obj:
						perm = getPermissions(line)
						subj = getSubject(line)
						if "write" in perm or "append" in perm:
							kernel_subject.add(subj)
							self.TCB.add(subj)
		for subj in kernel_subject:
			k_tag = subj+"_exec"
			with open(path, 'r') as f:
				for line in f:
					if "magisk" not in line:
						obj = line.split()[2]
						if k_tag in obj:
							subj = getSubject(line)
							perm = getPermissions(line)
							if "write" in perm or "append" in perm:
								kexec_writer.add(subj)
								self.TCB.add(subj)

	def construct_int_wall(self):
		print("Consturcting Integrity Wall......(a.k.a. looking for subject exec writer)")
		exec_writer = {}
		with open("./mac_policy/" + self.name, 'r') as f:
			for line in f:
				if "magisk" in line:
					continue
				subj = getSubject(line)
				obj = getObject(line)
				perm = getPermissions(line)

				#populate integrity wall with all possible subjects
				#populate other useful maps too!
				if subj in self.attr_map:
					for ssubj in self.attr_map[subj]:
						self.integrity_wall[ssubj] = set()
						self.subj_write_file[ssubj] = set()
						self.subj_write_dir[ssubj] = set()
						self.subj_read_file[ssubj] = set()
						self.subj_read_dir[ssubj] = set()
						self.subj_exec_file[ssubj] = set()

					self.integrity_wall[subj] = set()
					self.integrity_wall[subj] = set()
					self.subj_write_file[subj] = set()
					self.subj_write_dir[subj] = set()
					self.subj_read_file[subj] = set()
					self.subj_read_dir[subj] = set()
					self.subj_exec_file[subj] = set()


				if "_exec" in obj and ("write" in perm or "append" in perm):
					if obj not in exec_writer:
						exec_writer[obj] = set()
					#Populate all related domain if its attribute
					if subj in self.attr_map:
						for ssubj in self.attr_map[subj]:
							exec_writer[obj].add(ssubj)
					exec_writer[obj].add(subj)

		for subj in self.integrity_wall:
			key = subj + "_exec"
			if key in exec_writer:
				for writer in exec_writer[key]:
					#writers already attribute expanded
					self.integrity_wall[subj].add(writer)

	def populate_attribute(self, subj, obj, the_map):
		if subj in self.attr_map:
			if obj in self.attr_map:
				for lab in self.attr_map[subj]:
					for lab1 in self.attr_map[obj]:
						the_map[lab].add(lab1)
			else:
				for lab in self.attr_map[subj]:
					the_map[lab].add(obj)

		else:
			if obj in self.attr_map:
				for lab in self.attr_map[obj]:
					the_map[subj].add(lab)
		the_map[subj].add(obj)
	

	def construct_subj_permissions(self):
		with open("./mac_policy/" + self.name, 'r') as f:
			for line in f:
				if "magisk" in line:
					continue
				if "tmpfs" in line:
					continue
				subj = getSubject(line)
				perm = getPermissions(line)
				obj = getObject(line)
				sub_type = getObjectType(line)

				if ("read" in perm):
					if sub_type == "file":
						self.populate_attribute(subj, obj, self.subj_read_file)
					if sub_type == "dir":
						self.populate_attribute(subj, obj, self.subj_read_dir)

				if ("exec" in perm):
					if sub_type == "file":
						self.populate_attribute(subj, obj, self.subj_exec_file)

				if ("write" in perm  or "append" in perm):
					if sub_type == "file":
						self.populate_attribute(subj, obj, self.subj_write_file)
					if sub_type == "dir":
						self.populate_attribute(subj, obj, self.subj_write_dir)