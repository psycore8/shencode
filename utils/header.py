import random

header1 = """
  _______   __                      _______              __         
 |   _   | |  |--. .-----. .-----. |   _   | .-----. .--|  | .-----.
 |   1___| |     | |  -__| |     | |.  1___| |  _  | |  _  | |  -__|
 |____   | |__|__| |_____| |__|__| |.  |___  |_____| |_____| |_____|
 |:  1   |                         |:  1   |                        
 |::.. . |                         |::.. . |                        
 `-------\'                         `-------\'                      
 """

header2 = """
   .dMMMb     dMP dMP     dMMMMMP     dMMMMb    .aMMMb    .aMMMb     dMMMMb     dMMMMMP 
  dMP" VP    dMP dMP     dMP         dMP dMP   dMP"VMP   dMP"dMP    dMP VMP    dMP      
  VMMMb     dMMMMMP     dMMMP       dMP dMP   dMP       dMP dMP    dMP dMP    dMMMP     
dP .dMP    dMP dMP     dMP         dMP dMP   dMP.aMP   dMP.aMP    dMP.aMP    dMP        
VMMMP"    dMP dMP     dMMMMMP     dMP dMP    VMMMP"    VMMMP"    dMMMMP"    dMMMMMP     
"""

header3 = """
 .d8888b.  888                         .d8888b.                888          
d88P  Y88b 888                        d88P  Y88b               888          
Y88b.      888                        888    888               888          
 "Y888b.   88888b.   .d88b.  88888b.  888         .d88b.   .d88888  .d88b.  
    "Y88b. 888 "88b d8P  Y8b 888 "88b 888        d88""88b d88" 888 d8P  Y8b 
      "888 888  888 88888888 888  888 888    888 888  888 888  888 88888888 
Y88b  d88P 888  888 Y8b.     888  888 Y88b  d88P Y88..88P Y88b 888 Y8b.     
 "Y8888P"  888  888  "Y8888  888  888  "Y8888P"   "Y88P"   "Y88888  "Y8888  
"""

header4 = """
 :::===  :::  === :::===== :::= === :::===== :::====  :::====  :::=====
 :::     :::  === :::      :::===== :::      :::  === :::  === :::     
  =====  ======== ======   ======== ===      ===  === ===  === ======  
     === ===  === ===      === ==== ===      ===  === ===  === ===     
 ======  ===  === ======== ===  ===  =======  ======  =======  ========
"""

header5 = """
                                                               
 ____   ___  ______  _______   ____  ________    ____   ______ 
/ ___| |_  ||____  ||.  __  | / ___||.  ___  |  |__  | |____  |
\\___ \\   |_|  _  | | | |  | || |     | |   | |     | |   _  | |
 ___) |      | | |_| | | _| || |___  | |___| | ____| |  | | |_|
|____/       | |     |_||___| \\____| |_______|/____/\\_\\ | |    
             |_|                                        |_|    
"""

header6 = """
0.o Babe, I've shrinked the banner!
-----------------------------------
| [S].[H].[E].[N].[C].[O].[D].[E] |
-----------------------------------
"""

header7 = """
 111 1  1 1111 11  1 1111 1111 11    1111
 1   1  1 1    1 1 1 1    1  1 1  1  1
 111 1111 1111 1  11 1    1  1 1   1 1111
   1 1  1 1    1  11 1    1  1 1  1  1
 111 1  1 1111 1  11 1111 1111 11    1111
 - Resistance is futile -
"""

header8 = """
 $h3nC0d3 killed the banner !
"""

def get_header():
    rnd = random.randint(1, 8)
   # print(f'{rnd}')
    if rnd == 1:
        return header1
    elif rnd == 2:
        return header2
    elif rnd == 3:
        return header3
    elif rnd == 4:
        return header4
    elif rnd == 5:
        return header5
    elif rnd == 6:
        return header6
    elif rnd == 7:
        return header7
    elif rnd == 8:
        return header8