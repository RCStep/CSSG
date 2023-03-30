# Modified code from: https://blog.securehat.co.uk/process-injection/shellcode-execution-via-enumsystemlocala and https://github.com/boku7/Ninja_UUID_Runner/blob/main/bin2uuids.py
#!usr/bin/python3

from uuid import UUID
import sys

if len(sys.argv) < 2:
    print("Usage: %s <shellcode_file> <output_file>" % sys.argv[0])
    sys.exit(1) 

def uuid(in_file, out_file):
    sys.stdout = open(out_file, 'w')

    with open(in_file, "rb") as f:
        chunk = f.read(16)
        while chunk:
            if len(chunk) < 16:
                padding = 16 - len(chunk)
                chunk = chunk + (b"\x90" * padding)
                print("{}\"{}\"".format(' '*8,UUID(bytes_le=chunk)))
                break
            print("{}\"{}\",".format(' '*8,UUID(bytes_le=chunk)))
            chunk = f.read(16)

uuid((sys.argv[1]), (sys.argv[2]))