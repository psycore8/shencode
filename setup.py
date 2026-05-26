from setuptools import setup, find_packages
from utils.helper import FirstRun

extras = []
import sys
fr = FirstRun()
if sys.platform == 'win32':
    extras.append(
        ['pywin32==311',
        'WMI==1.5.1']
        )
    fr.WinOnlyModules(True)
elif sys.platform == 'linux':
    #extras.append('linux-only-package')
    fr.WinOnlyModules(False)
elif sys.platform == 'darwin':
    pass
    #extras.append('macos-only-package')

setup(
    name='ShenCode',
    version='1.0.0',
    author='psycore8',
    description='A versatile tool for working with shellcodes',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/psycore8/shencode',
    packages=[
        'shencode',
        'modules',
        'utils'
    ],
    install_requires=[
        'capstone==5.0.7',
        'certifi==2026.5.20',
        'cffi==2.0.0',
        'charset-normalizer==3.4.7',
        'colorama==0.4.6',
        'cryptography==48.0.0',
        'feedparser==6.0.12',
        'idna==3.16',
        'keystone-engine',
        'lxml==6.1.0',
        'OpenCv-python==4.13.0.92',
        'pefile==2024.8.26',
        "prompt_toolkit==3.0.52",
        'psutil==7.2.2',
        'pycparser==3.0',
        'pypng==0.20220715.0',
        'pyzbar==0.1.9',
        'qrcode==8.2',
        'requests==2.34.2',
        'rich==15.0.0',
        'setuptools==82.0.1',
        'sgmllib3k==1.0.0',
        'tqdm==4.67.3',
        'typing_extensions==4.15.0',
        'yaspin==3.4.0',
        'urllib3==2.7.0',
        ] + extras,
        entry_points={
            'console_scripts': [
                'shencode=shencode:main'
            ]
        }
)