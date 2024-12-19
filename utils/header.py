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

def get_header():
    rnd = random.randint(1, 3)
    print(f'{rnd}')
    if rnd == 1:
        return header1
    elif rnd == 2:
        return header2
    elif rnd == 3:
        return header3