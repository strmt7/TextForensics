import sys
sys.path.insert(0, 'C:/Users/strat/Documents/Default Project/src')

import coverage
cov = coverage.Coverage(source=['textforensics', 'textforensics.report', 'textforensics.detectors'])
cov.start()

import unittest
loader = unittest.TestLoader()
suite = unittest.TestSuite()

# Load all tests
suite.addTests(loader.discover('tests', pattern='test_*.py'))

runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)

cov.stop()
cov.save()

print()
print('='*60)
print('COVERAGE REPORT')
print('='*60)
cov.report()