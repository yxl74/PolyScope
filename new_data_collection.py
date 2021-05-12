from ppadb.client import Client as AdbClient
import argparse
import sys, os
# Default is "127.0.0.1" and 5037

#Add graph capability 


class Phone:

	def __init__(self, device_name):
		client = client = AdbClient(host="127.0.0.1", port=5037)
		devices = client.devices()
		self.device = devices[0]
		self.name = device_name

	def shell(self, command):
		self.device.shell("ls")

	def handler(self, connection):
		while True:
			data = connection.read_all()
			if not data:
				break
			data = data.decode('utf-8')
			lst = data.split("\n")
			self.package_list = lst
				#self.device.shell("am start " + pkg_name)

		connection.close()
	
	#get process subgroup info
	def get_subgroup(self):
		self.device.push("subgroup.sh", "/sdcard/Download/subgroup.sh")
		self.device.shell("su -c \"mv /sdcard/Download/subgroup.sh /data/adb \"")
		self.device.shell("su -c \"chmod 777 /data/adb/subgroup.sh \"")
		self.device.shell("su -c \"/data/adb/subgroup.sh\"")
		self.device.shell("su -c \"rm /data/adb/subgroup.sh\"")
		self.device.pull("/sdcard/subgroup", "./subgroup/"+self.name)
		self.device.shell("su -c \"rm /sdcard/subgroup\"")

	def start_packages(self):
		self.device.shell("pm list packages -f", handler=self.handler)


		#self.device.pull("/sdcard/packages", "./pacakges/" + self.name)
		#self.device.shell("su -c \"rm /sdcard/packages\"")
		for line in self.package_list:
			fp = line[line.find("package:")+8:line.find(".apk")+4]
			folder = ""
			pkg_name = line[line.find(".apk")+5:]
			self.device.shell("am start " + pkg_name)



	def get_ps(self):
		self.device.shell("su -c \"ps -A -o label:40,user:20,group:20,ARGS:60,COMMAND,PID > /sdcard/ps\"")
		self.device.pull("sdcard/ps", "./ps-Z-list/" + self.name)
		self.device.shell("su -c \"rm /sdcard/ps\"")


	def get_ls(self):
		self.device.shell("su -c \"ls -lRZ > /sdcard/ls\"")
		self.device.pull("/sdcard/ls", "./ls_lRZ/" + self.name + "_raw")
		self.device.shell("su -c \"rm /sdcard/ls\"")

	def get_emulated(self):
		self.device.shell("su -c \"ls -lRZ /storage/emulated/0 > /sdcard/ls_emu\"")
		self.device.pull("/sdcard/ls_emu", "./ls_lRZ/" + self.name + "_raw_emu")
		self.device.shell("su -c \"rm /sdcard/ls_emu\"")

	#def get_mediaProvider_db(self):
		


	def form_ls(self):
		wf = open("./ls_lRZ/" + self.name, 'w')
		wf1 = open("./ls_lRZ/" + self.name + "_emu", 'w')

		with open("./ls_lRZ/" + self.name + "_raw") as f:
			#Increase efficiency remove files only writable to root
			obj_name = ""
			for line in f:
				if line.startswith("."):
					if line.startswith(".:"):
						obj_name = "/"
					else:
						obj_name = line[1:-2] + "/"
				if line[0] == 'd' or line[0] == '-':
					if obj_name.startswith("/proc"):
						continue
					cur_line = line.split()
					perm = cur_line[0]
					owner = cur_line[2]
					group = cur_line[3]

					if line[0] == '-' and owner == "root" and group == "root" and perm[8] != 'w':
						#Increase efficiency remove files only writable to root
						continue


					SE = cur_line[4]
					SEsplit = SE.split(":")
					label = SEsplit[2]
					cat = ""
					if len(SEsplit) > 4:
						#Has Category
						cat = SEsplit[4]
					full_path = obj_name + line.split()[8]

					if cat == "":
						wf.write(perm + "  "+ owner + "  " + group + "  " + label + " " + full_path + "\n")
					else:
						wf.write(perm + "  "+ owner + "  " + group + "  " + label + ":" + cat + " " + full_path+ "\n")
		
		with open("./ls_lRZ/" + self.name + "_raw_emu") as f:
			#Increase efficiency remove files only writable to root
			obj_name = ""
			for line in f:
				if line.startswith("/"):
						obj_name = line[:-2] + "/"
				if line[0] == 'd' or line[0] == '-':
					if obj_name.startswith("/proc"):
						continue
					cur_line = line.split()
					perm = cur_line[0]
					owner = cur_line[2]
					group = cur_line[3]

					if line[0] == '-' and owner == "root" and group == "root" and perm[8] != 'w':
						#Increase efficiency remove files only writable to root
						continue


					SE = cur_line[4]
					SEsplit = SE.split(":")
					label = SEsplit[2]
					cat = ""
					if len(SEsplit) > 4:
						#Has Category
						cat = SEsplit[4]
					full_path = obj_name + line.split()[8]

					if cat == "":
						wf1.write(perm + "  "+ owner + "  " + group + "  " + label + " " + full_path + "\n")
					else:
						wf1.write(perm + "  "+ owner + "  " + group + "  " + label + ":" + cat + " " + full_path+ "\n")
		wf.close()
		wf1.close()

	def get_mac(self):
		self.device.shell("su -c \"cat /sys/fs/selinux/policy > /sdcard/sepolicy\"")
		self.device.pull("/sdcard/sepolicy", "./mac_policy/" + self.name + "_raw")
		self.device.shell("su -c \"rm /sdcard/sepolicy\"")

		os.system("sesearch --allow ./mac_policy/" + self.name +  "_raw > ./mac_policy/" +self.name)


	def get_attribute(self):
		os.system("seinfo -a -x ./mac_policy/" + self.name +  "_raw > ./attribute_file/" + self.name)
		file = open("./attribute_file/tmp", 'w')
		with open("./attribute_file/" + self.name) as f:
			for line in f:
				if line != "\n":
					file.write(line)
		os.system("mv ./attribute_file/tmp ./attribute_file/" + self.name)


	#Collect Subroup, MAC policy, MAC attribute, DAC ls, Process Mapping
	def collect_data(self):
		print("Getting Subgroup")
		self.get_subgroup()
		print("Getting MAC data")
		self.get_mac()
		self.get_attribute()
		print("Getting ls")
		self.get_ls()
		self.get_emulated()
		self.form_ls()
		os.remove("./ls_lRZ/" + self.name + "_raw")
		os.remove("./ls_lRZ/" + self.name + "_raw_emu")
		print("Starting packages, and getting ps")
		self.start_packages()
		self.get_ps()

def init_directories():
	if not os.path.isdir("./attribute_file"):
		os.mkdir("./attribute_file")
	if not os.path.isdir("./subgroup"):
		os.mkdir("./subgroup")
	if not os.path.isdir("./dac_result"):
		os.mkdir("./dac_result")
	if not os.path.isdir("./mac_policy"):
		os.mkdir("./mac_policy")
	if not os.path.isdir("./ls_lRZ"):
		os.mkdir("./ls_lRZ")
	if not os.path.isdir("./ps-Z-list"):
		os.mkdir("./ps-Z-list")



if __name__ == "__main__":
	init_directories()

	parser = argparse.ArgumentParser()
	parser.add_argument("-n", "--name", dest = "name", default = None,
						help = "Specify device name")
	args = parser.parse_args()
	device_name = args.name
	phone1 = Phone(device_name)
	phone1.collect_data()