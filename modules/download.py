import requests
#from utils.helper import GetFileInfo
from utils.style import *
from tqdm import tqdm

CATEGORY    = 'core'
DESCRIPTION = 'Download files'

cs = ConsoleStyles()

arglist ={
    'output':               { 'value': None, 'desc': 'Output file' },
    'protocol':             { 'value': None, 'desc': 'Download protocol: http' },
    'uri':                  { 'value': None, 'desc': 'URI to file' }
}

def register_arguments(parser):
    parser.add_argument('-o', '--output', required=True, help=arglist['output']['desc'])
    parser.add_argument('-p', '--protocol', choices=['http'], required=True, help=arglist['protocol']['desc'])
    parser.add_argument('-u', '--uri', required=True, help=arglist['uri']['desc'])

class module:
    Author = 'psycore8'
    Version = '0.9.0'
    DisplayName = 'D0WNL04D3R'
    data_size = int
    hash = ''
    data_bytes = bytes
    relay_output = False
    shell_path = '::core::download'

    def __init__(self, output, protocol, uri):
        self.output = output
        self.protocol = protocol
        self.uri = uri

    def process(self):
        cs.module_header(self.DisplayName, self.Version)
        if hasattr(self, self.protocol):
            processed_data = getattr(self, self.protocol)()
            if not processed_data:
                cs.print('Error during download', cs.state_fail)
                return
            if self.relay_output:
                return processed_data
            if processed_data != True:
                cs.print('Trying to write output file...', cs.state_note)
                self.save_file(processed_data)
                cs.action_save_file2(self.output)
        else:
            cs.print(f'Protocol {self.protocol} is not valid!', cs.state_fail)
        cs.print('DONE!', cs.state_ok)

    def http(self):
        data = any
        r = requests.head(self.uri, allow_redirects=True)
        if 'Content-Length' in r.headers:
            size_bytes = int(r.headers['Content-Length'])
            cs.print(f'File size: {size_bytes} bytes', cs.state_note)
            self.download_with_progress(self.uri, self.output)
            data = True
        else:
            cs.print('Content header not available, download without progress...', cs.state_note)
            data = self.download_without_progresss()
        return data
    
    def download_with_progress(self, url, output_path):
        response = requests.get(url, stream=True)
        total = int(response.headers.get('Content-Length', 0))
        chunk_size = 8192 

        with open(output_path, 'wb') as f, tqdm(
            total=total,
            unit='B',
            unit_scale=True,
            desc="Download",
            ncols=80,
            colour='magenta'
        ) as progress:
            downloaded = 0
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk: 
                    f.write(chunk)
                    downloaded += len(chunk)
                    progress.update(len(chunk))
            cs.print('\n')
            cs.action_save_file2(self.output)

    def download_without_progresss(self):
        r = requests.get(self.uri)
        if r.status_code == 200:
            return r._content
        else:
            return False
        
        
        
    def save_file(self, data):
        try:
            with open(self.output, 'wb') as f:
                f.write(data)
            return True
        except:
            return False