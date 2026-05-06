# C3 - A Modular Steganographic Remote Access Trojan
*Command, Control, Customise!*

**Disclaimer:** This project was designed for testing antimalware software in a safe environment. I am not responsible for and do not condone any malicious usage of the system. I will also not be providing a frontend for the Trojan.

## Overview
C3 is an open-source **Modular Remote Access Trojan (RAT)** designed to allow for easy testing of antimalware software against a large variety of different attacks.

---

## Features

- **Steganographic Data Transfer**  
    Inspired by stegomalware, module data is transmitted via steganography to provide an extra challenge for antimalware software

- **Fully Modular System**  
  The "bad actor" is fully able to customise which modules are transmitted per message, with proper dependency support

- **Encrypted Data Transfer**  
  All data is transmitted using AES-256 in order to mimic real-world data transfer systems

- **Easy Module Access**  
  All modules can be easily viewed and accessed from the "bad actor" client, with intuitive support for module updates and querying

- **C++ Implementation**  
  C++ is used both for the modules and for the system core, allowing for optimisation and low level access required to write the "malware" used for testing

---

## Architecture Overview

- **Python** is used to form the backend of the project
    - The **socket** module is used to handle connections using the **TCP** protocol
    - **AES** is used through the **cryptography** module in order to emulate real-world transmissions
    - **SQL** is used to track users and messages using **sqlite3**
    - **Pillow** is used for the image processing required for steganographic embedding
- **C++** is used for the module runner and the modules, with modules being transmitted in **DLL** form

---

## Learning Results

- I learnt how to **setup modular architecture** and the important tenets of **scalable design**

- I improved my **steganography** skills and better learnt how to optimise for security

- I improved my **file management** skills in order to better implement this application

- I learnt **how to work with DLL files in C++** in order to run the application

- Whilst conducting research for the project I learnt more about **antimalware and how it functions** in order to better understand the system target. 

--- 

## Future Improvements

- **TURN** implemenation to deal with NAT Traversal

- **Multi-OS System Support** to allow for multiple DLLs to be stored for different systems and versions

- **DoS protection** to stop malicious actors being able to disable the network by spamming it