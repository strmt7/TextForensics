#!/usr/bin/env python
import subprocess
import sys

result = subprocess.run([
    sys.executable,
    '-m', 'pytest',
    'C:\\\\Users\\\\strat\\\\Documents\\\\Default Project\\\\tests\\\\test_webapp.py',
    '--cov=textforensics',
    '--cov-report=term-missing',
    '--cov-branch',
    '-v',
    '-p', 'no:cacheprovider',
    '--tb=short'
], cwd='C:\\\\Users\\\\strat\\\\Documents\\\\Default Project', timeout=120)
sys.exit(result.returncode)