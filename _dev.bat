@echo off
python3.12 shencode.py extract -f dev\xor-decoder.o -o dev\xor.raw -fb 60 -lb 328
python3.12 shencode.py output -f dev\xor.raw -s c