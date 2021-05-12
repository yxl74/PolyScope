# PolyScope (Currently under construction to adapt Scoped Storage)

## What is Polyscope?
Polyscope is a tool that computes attack surface on Android file system. Polyscope is able to take multiple access control mechanisms into its computation(e.g. MAC, DAC), and presents attack surface in the form of Integrity Violations(IV). IV defines possible data flows from lower integrity domain to high integriy domain. For details please check out the original PolyScope [paper](https://www.usenix.org/conference/usenixsecurity21/presentation/lee-yu-tsung). 

## Why Polyscope?
Polyscope can be useful for access control policy writers and software developers. Polyscope can identify policy misconfigurations that could lead to vulnerabilities, and highlight domains that needs further testing(e.g. ones with a lot of possible risky data flow).

## Requirements
Polyscope is implemented in python, with some bash scripts for autoatic data collection. Therefore, python3 is required on your system. Also, Polyscope relies on adb(Android Debug Bridge) to collect data, and SEtool to extract MAC policies. We also need python's adb library pyadb.
