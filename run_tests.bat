@echo off
cd /d "C:\Users\strat\Documents\Default Project"
"C:\Users\strat\AppData\Local\Temp\opencode\tv\Scripts\python.exe" -m pytest tests/test_webapp.py --cov=textforensics --cov-report=term-missing --cov-branch -v -p no:cacheprovider --tb=short
pause