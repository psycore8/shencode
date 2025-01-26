import argparse

parser = argparse.ArgumentParser(description="create and obfuscate shellcodes")
subcommands = {}
subparser = parser.add_subparsers(dest='command')

def CreateMainParser():
    parser.add_argument("--version", action='store_true', help="show version info")

def CreateSubParser(
        SubParserName,SubParserHelp,ArgumentList=list):
    parser_name = SubParserName
    subcommands['parser_name'] = subparser.add_parser(parser_name, help=SubParserHelp)
    for row in ArgumentList:
        if len(row[2]) > 0 and len(row[3]) == 0:
            spChoices = row[2].split(',')
            #print(f'{spChoices}')
            subcommands['parser_name'].add_argument(
                row[0],
                row[1],
                choices=spChoices,
                help=row[4]
                )
        elif len(row[2]) == 0 and len(row[3]) > 0:
            #print(f'{row[3]}')
            subcommands['parser_name'].add_argument(
                row[0],
                row[1],
                action=row[3],
                help=row[4]
                )
        else:
            subcommands['parser_name'].add_argument(
                row[0],
                row[1],
                help=row[4]
                )
            
def CreateSubParserEx(
        SubParserName,SubParserHelp,ArgumentList=list):
    parser_name = SubParserName
    subcommands['parser_name'] = subparser.add_parser(parser_name, help=SubParserHelp)
    for row in ArgumentList:
        # flag, name, choices=, action=, default=, type, required, help)
        subcommands['parser_name'].add_argument(
            row[0],
            row[1],
            choices=row[2],
            action=row[3],
            default=row[4],
            type=row[5],
            required=row[6],
            help=row[7],
        )
        # if len(row[2]) > 0 and len(row[3]) == 0:
        #     spChoices = row[2].split(',')
        #     #print(f'{spChoices}')
        #     subcommands['parser_name'].add_argument(
        #         row[0],
        #         row[1],
        #         choices=spChoices,
        #         help=row[4]
        #         )
        # elif len(row[2]) == 0 and len(row[3]) > 0:
        #     #print(f'{row[3]}')
        #     subcommands['parser_name'].add_argument(
        #         row[0],
        #         row[1],
        #         action=row[3],
        #         help=row[4]
        #         )
        # else:
        #     subcommands['parser_name'].add_argument(
        #         row[0],
        #         row[1],
        #         help=row[4]
        #         )

def ParseArgs(MainArgs):
    #args = parser.parse_args(MainArgs)
    return parser.parse_args(MainArgs)
