from setuptools import setup

setup(
    name='pystrike',
    version='0.1',
    py_modules=['pystrike'],
    install_requires=[
        'Click',
        'crowdstrike-falconpy',
        'boto3'
    ],
    entry_points='''
        [console_scripts]
        pystrike=pystrike:falcon
    ''',
)