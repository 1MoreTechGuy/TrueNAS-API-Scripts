"""debug.py

Debug script to troubleshoot issues on semaphore or other script automation
platforms and runners

Acknowledgement:
This file was created with the assistance of GitHub Copilot. Review and
testing were performed by the author.

"""

import os

print("==  ENVIRONMENT VARIABLES  ==\n===     START OUTPUT      ===\n")

for key, value in os.environ.items():
    print(f"{key}={value}")

print("\n===     END OUTPUT      ===\n")