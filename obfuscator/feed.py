import utils.arg
import datetime
from lxml import etree

class feed_obfuscator:
    Author = 'psycore8'
    Description = 'obfuscate shellcodes as XML Feed'
    Version = '1.0.0'
    feed_fake_uri = 'https://www.microloft.com/'
    feed_fake_title = 'Developer News'
    feed_fake_subtitle = 'The latest developer news from microloft.com'
    feed_fake_author = 'Bill Ports'
    feed_fake_ids = []
    shellcode = ''

    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.output_file = output_file


    def init():
        spName = 'feed'
        spArgList = [
            ['-i', '--input', '', '', 'Input file for feed obfucsation'],
            ['-o', '--output', '', '', 'Output file for feed obfucsation']
        ]
        utils.arg.CreateSubParser(spName, feed_obfuscator.Description, spArgList)

    def open_file(self):
        try:
            for b in open(self.input_file, 'rb').read():
                self.shellcode += b.to_bytes(1, 'big').hex()
            return True
        except FileNotFoundError:
            return False

    def convert_bytes_to_fake_id(self, block_size=16):
        s = self.shellcode.encode('utf-8')
        self.feed_fake_ids.extend([s[i:i + block_size] for i in range(0, len(s), block_size)])
        print(f'{self.feed_fake_ids}')


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
        with open(self.output_file, "wb") as file:
            file.write(xml_str)

