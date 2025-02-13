from setuptools import setup, find_packages
from utils.helper import FirstRun

extras = []
import sys
if sys.platform == 'win32':
    extras.append(
        ['pywin32==306',
        'WMI==1.5.1']
        )
    FirstRun.WinOnlyModules(True)
elif sys.platform == 'linux':
    #extras.append('linux-only-package')
    FirstRun.WinOnlyModules(False)
elif sys.platform == 'darwin':
    pass
    #extras.append('macos-only-package')

setup(
    name='ShenCode',
    version='0.7.1',
    author='psycore8',
    description='A versatile tool for working with shellcodes',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/psycore8/shencode',
    #packages=find_packages(),
    packages=[
        'modules',
        'utils'
    ],
    install_requires=[
        'capstone==5.0.3',
        'certifi==2024.12.14',
        'cffi==1.17.1',
        'charset-normalizer==3.4.1',
        'colorama==0.4.6',
        'cryptography==43.0.3',
        'feedparser==6.0.11',
        'idna==3.10',
        'lxml==5.3.0',
        'pefile==2024.8.26',
        'pycparser==2.22',
        'pypng==0.20220715.0',
        'qrcode==7.4.2',
        'requests==2.32.3',
        'setuptools==75.8.0',
        'sgmllib3k==1.0.0',
        'typing_extensions==4.12.2',
        'urllib3==2.3.0',
        
        ] + extras,
        py_modules=['shencode'],
        # py_modules=[
        #     'shencode',
        #     'modules',
        #     'utils'
        # ],
        entry_points={
            'console_scripts': [
                'shencode=shencode:main'
            ]
        }
)