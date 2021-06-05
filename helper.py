#!/usr/bin/env python

#This source code includes helper function to parse policy files


#MAC policy parsing helpers
def get_mac_attacker_label(dic_mac_entry):
  return dic_mac_entry.split()[0]

def get_mac_victim_label(dic_mac_entry):
  return dic_mac_entry.split()[4]

def get_mac_object_label(dic_mac_entry):
  return dic_mac_entry.split()[1]

def get_mac_object_type(dic_mac_entry):
  return dic_mac_entry.split()[3]

def get_mac_object_whole(dic_mac_entry):
  return dic_mac_entry.split()[1] + " : " + dic_mac_entry.split()[3]

def getSubject(line):
	return line.split()[1]

def getObject(line):
	return line.split()[2].split(':')[0]

def getObjectType(line):
  return line.split()[2].split(':')[1]

def getPermissions(line):
  if line[-3] == "}" or line[-4] == "}": # multiple permissions
    return line[line.find("{")+1:line.find("}")][1:]
  else: # single permission
    return line.split()[-1][:-1]


#DAC Policy parsing helpers

def get_dac_perms(dac_entry):
  return dac_entry.split()[0]

def get_dac_owner(dac_entry):
  return dac_entry.split()[1]

def get_dac_group(dac_entry):
  return dac_entry.split()[2]

def get_dac_obj_label(dac_entry):
  return dac_entry.split()[3]

def get_dac_filename(dac_entry):
  return dac_entry.split()[4]