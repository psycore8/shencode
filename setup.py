from setuptools import setup, find_packages
from utils.helper import FirstRun

extras = []
import sys
if sys.platform == 'win32':
    extras.append(
        ['pywin32==310',
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
    version='0.8.4',
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
        'capstone==5.0.6',
        'certifi==2025.7.14',
        'cffi==1.17.1',
        'charset-normalizer==3.4.2',
        'colorama==0.4.6',
        'cryptography==45.0.5',
        'feedparser==6.0.11',
        'idna==3.10',
        'keystone-engine',
        'lxml==6.0.0',
        'pefile==2024.8.26',
        "prompt_toolkit",
        'psutil',
        'pycparser==2.22',
        'pypng==0.20220715.0',
        'qrcode==8.2',
        'requests==2.32.4',
        'setuptools==80.9.0',
        'sgmllib3k==1.0.0',
        'tqdm',
        'typing_extensions==4.14.1',
        'urllib3==2.5.0',
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