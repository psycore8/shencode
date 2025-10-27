from setuptools import setup, find_packages
from utils.helper import FirstRun

extras = []
import sys
fr = FirstRun()
if sys.platform == 'win32':
    extras.append(
        ['pywin32==310',
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
    version='0.9.0',
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
        'capstone==5.0.6',
        'certifi==2025.10.5',
        'cffi==2.0.0',
        'charset-normalizer==3.4.4',
        'colorama==0.4.6',
        'cryptography==46.0.3',
        'feedparser==6.0.12',
        'idna==3.11',
        'keystone-engine',
        'lxml==6.0.2',
        'OpenCv-python==4.12.0.88',
        'pefile==2024.8.26',
        "prompt_toolkit==3.0.52",
        'psutil==7.0.0',
        'pycparser==2.23',
        'pypng==0.20220715.0',
        'pyzbar==0.1.9',
        'qrcode==8.2',
        'requests==2.32.5',
        'rich==14.2.0',
        'setuptools==80.9.0',
        'sgmllib3k==1.0.0',
        'tqdm==4.67.1',
        'typing_extensions==4.15.0',
        'urllib3==2.5.0',
        'yaspin==3.2.0'
        ] + extras,
        entry_points={
            'console_scripts': [
                'shencode=shencode:main'
            ]
        }
)