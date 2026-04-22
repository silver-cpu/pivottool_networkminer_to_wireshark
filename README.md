------------------------------
## NetworkMiner Forensic Bridge & HUD

A C++ DLL + EXE designed to augment NetworkMiner with real-time UI scraping, an overlay HUD, and "Pivot" capabilities into Wireshark and TShark.

------------------------------
## Overview

The Forensic Bridge acts as an intelligence layer sitting on top of NetworkMiner. It utilizes the Microsoft UI Automation API to programmatically "read" the data currently selected or visible within the NetworkMiner interface. This data is then displayed in a topmost HUD and can be instantly pivoted into deep-packet analysis tools with pre-generated filters.
## Key Features

* Real-Time UI Scraper: Dynamically extracts Frame Numbers, IPs, MAC addresses, and Protocols from selected rows.
* Smart Pivot: Automatically generates Wireshark display filters (e.g., frame.number == X || ip.addr == Y) based on your current selection.
* HUD Overlay: A persistent WS_EX_TOPMOST window that keeps critical forensic data visible even when switching between applications.
* Multi-Tool Support: Seamlessly toggle between Wireshark (GUI) and TShark (CLI) for your pivot operations.
* Process Management: Built-in ability to "clean" the workspace by terminating existing analysis processes before launching new ones.

------------------------------
## Technical Architecture

The project is structured as a multi-threaded Windows DLL:

   1. UI Thread: Manages the Win32 HUD window, button interactions, and the message loop.
   2. Scraper Worker Thread: Utilizes IUIAutomation to crawl the NetworkMiner window tree, identifying .pcap references and selected table cells.
   3. Smart Pivot Engine: Maps scraped data to Wireshark command-line arguments using regex sanitization for IP/MAC integrity.

------------------------------
## Prerequisites

* NetworkMiner (v3.1 recommended, if you want to change the version type, you'll need to edit the "dllmain.cpp").
* Wireshark (Installed and added to your System PATH).
* Windows 10/11 (Required for UI Automation Core).

## Installation

(if you do not want to run my dll and want to compile yourself)
   1. Compile the source into a .dll (Architecture must match your NetworkMiner version, I chose Release x64).
   2. Place a folder into NetworkMiner's exe directory.
   3. Place into that folder the bridge_for_networkminer.dll, the network_miner_to_wireshark.exe, and the .pcap file that you wish to examine

## Environment Setup

To use the TShark (CLI) feature, ensure the Wireshark directory is in your system environment variables:
Control Panel > System > Advanced System Settings > Environment Variables > Path > New > C:\Program Files\Wireshark\

------------------------------
## Usage: The HUD Interface

* PIVOT: Launches Wireshark/TShark with a filter specifically for the rows you have highlighted in NetworkMiner.
* EXPORT: Saves the current "Forensic Inspector" view to EXPORTED.txt in the DLL directory.
* Kill Existing: If checked, it will close all open Wireshark windows before starting a new pivot to prevent workspace clutter.
* Use TShark: Switches the output from the Wireshark GUI to a Command Prompt running TShark.

------------------------------
## ⚠️ Safety & Compliance

* Disclaimer: This tool is for authorized forensic analysis and educational purposes only.

------------------------------
## STARTING?

   1. Download the .exe, and .dll
   2. Place a folder into NetworkMiner's exe directory.
   3. Place into that folder the bridge_for_networkminer.dll, the network_miner_to_wireshark.exe, and the .pcap file that you wish to examine

------------------------------

Developed for Forensic Analysts
by: Matteen Mahfooz

