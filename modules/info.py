from utils.helper import nstate as nstate

CATEGORY = 'core'

def register_arguments(parser):
    parser.add_argument('-g', '--get', action='store_true', help='Get developer info')
    parser.add_argument('-m', '--modlist', action='store_true', help='List modules')

class develop:
    import utils.header as header
    from os import listdir, path
    Author = 'psycore8'
    Description = 'AES encoder for payloads'
    Version = '0.0.1'
    DisplayName = 'SHENCODE-DEViNFO'
    mod_count = 0
    mod_name = ''
    data_size = int
    hash = ''

    def __init__(self, version=str, mod_dir=str, modlist=False):
        self.version = version
        self.mod_dir = mod_dir
        self.modlist = modlist

    def msg(self, message_type, ErrorExit=False):
        messages = {
            'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
            #'error.input'    : f'{nstate.s_fail} File {self.input_file} not found or cannot be opened.',
            #'error.enc'      : f'{nstate.s_fail} En-/Decrption error, aborting script execution',
            #'error.mode'     : f'{nstate.s_fail} Please provide a valid mode: encode / decode',
            'banner'         : f'{nstate.s_ok} Banner count: {len(self.header.headers)}',
            'version'        : f'{nstate.s_ok} ShenCode Version: {self.version}',
            'mods'           : f'{nstate.s_ok} Module count: {self.mod_count}',
            'repo'           : f'{nstate.s_ok} Repository: {nstate.f_link}https://github.com/psycore8/shencode{nstate.f_end}',
            'modlist.s'      : f'{nstate.s_ok} List modules',
            'modlist'        : f'{nstate.s_note} Module {self.mod_count}: {self.mod_name}',
            'post.done'      : f'{nstate.s_ok} DONE!'
            #'proc.out'       : f'{nstate.s_ok} File created in {self.output_file}\n{nstate.s_ok} Hash: {self.hash}'
        }
        print(messages.get(message_type, f'{message_type} - this message type is unknown'))
        if ErrorExit:
            exit()

    def get_mod_count(self):
        self.mod_count = len([f for f in self.listdir(self.mod_dir) if self.path.isfile(self.path.join(self.mod_dir, f))])

    def get_modlist(self):
        for file in self.listdir(self.mod_dir):
            if file.endswith(".py") and not file.startswith("__"):
                mod_name = file[:-3] 
                return mod_name

    def process(self):
        self.msg('pre.head')
        self.msg('version')
        self.msg('banner')
        self.get_mod_count()
        self.msg('mods')
        self.msg('repo')
        if self.modlist:
            self.mod_count = 1
            for file in self.listdir(self.mod_dir):
                if file.endswith(".py") and not file.startswith("__"):
                    self.mod_name = file[:-3] 
                    self.msg('modlist')
                    self.mod_count += 1
        self.msg('post.done')
                
