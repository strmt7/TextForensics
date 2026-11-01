@echo off
"C:\Users\strat\AppData\Local\Temp\opencode\tfv\Scripts\python.exe" -m pytest "C:\Users\strat\Documents\Default Project\tests\test_webapp.py" --cov=textforensics --cov-report=term-missing --cov-branch -v -p no:cacheprovider --tb=short
pause