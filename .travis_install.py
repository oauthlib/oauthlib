import sys
import subprocess

if sys.version_info[0] == 2:
    subprocess.call(['pip', 'install', 'unittest2'])
