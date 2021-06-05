# PolyScope (Currently under construction to adapt Scoped Storage)

## What is Polyscope?
Polyscope is a tool that computes attack surface on Android file system. Polyscope is able to take multiple access control mechanisms into its computation(e.g. MAC, DAC), and presents attack surface in the form of Integrity Violations(IV). IV defines possible data flows from lower integrity domain to high integriy domain. For details please check out the original PolyScope [paper](https://www.usenix.org/conference/usenixsecurity21/presentation/lee-yu-tsung). 

## Why Polyscope?
Polyscope can be useful for access control policy writers and software developers. Polyscope can identify policy misconfigurations that could lead to vulnerabilities, and highlight domains that needs further testing(e.g. ones with a lot of possible risky data flow).


## Usage
# Dependencies
Python3, pure python adb(ppadb), adb


## Data Collection
With adb daemon running, simply run:
`python3 new_data_collection.py -n <device_name>`

You are free to name the device, just remember the name you use since we need that for the next step.

## Running Anlysis
To simplified the analysis, Polyscope now combines 
'python3 polyscope.py -n <device_name> -p <thread_count>'

The result of Polyscope will locate in ./dac_result/<device_name>, specifying 4 kinds Integrity-Violations:
Read-IV, Write-IV, Binding-IV, Pathname-IV
