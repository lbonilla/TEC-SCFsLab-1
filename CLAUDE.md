# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an educational security laboratory (SSCFs Lab 1) demonstrating Modbus TCP protocol vulnerabilities. The project documents hands-on security analysis of unencrypted industrial control protocol traffic.

## Lab Environment Setup

```bash
# System packages
sudo apt update
sudo apt install python3-pip wireshark -y

# Python libraries for Modbus and packet analysis
sudo pip3 install pymodbus scapy
```

## Building the Lab Report

The lab report is written in LaTeX. To compile:

```bash
cd SSCFs_LAB1
pdflatex main.tex
```

## Project Structure

- `SSCFs_LAB1/` - LaTeX lab report with screenshots documenting the procedure
- `breakinModbus.pdf`, `caso1.pdf` - Reference materials

## Lab Focus Areas

The lab demonstrates defensive security analysis of Modbus TCP:
- Traffic interception and analysis using Wireshark
- Packet inspection with Scapy
- Documentation of protocol vulnerabilities (lack of encryption, authentication, and integrity protection)

## Important Notes

- All lab work is conducted in isolated virtual machine environments
- This is educational material for understanding industrial protocol security weaknesses
- The pymodbus server/client code is executed within the VM during the lab (not stored in repo)
