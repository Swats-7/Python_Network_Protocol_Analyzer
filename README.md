# Network Protocol Analyzer 

# Description 
This is a custom network command line network protocol analyzer .

## The Problem
Most open source intrusion detection systems (which are built on top of network protocol analyzers) have limited customizability for personal use.

## How It Works

- On execution the program starts capturing data to and from your device.
- It prints the parsed data into the CLI until a person quits by pressing 'q'.
- The packets are printed as is unless a filter is specified. 