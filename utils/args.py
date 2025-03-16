import argparse
import importlib
import os
from textwrap import wrap

Modules_Dir = 'modules'

class FixedWidthHelpFormatter(argparse.HelpFormatter):
    def _split_lines(self, text, width):
        return wrap(text, width)

    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)

        parts = ", ".join(action.option_strings)

        if len(parts) > 25:
            return "\n".join(wrap(parts, width=25))
        return parts
    
def load_modules():
    modules = {}
    for file in os.listdir(Modules_Dir):
        if file.endswith(".py") and not file.startswith("__"):
            ### to sort categories ASC rename file category-modulename.py
            # mod_name = file.split('-')[1][:-3]
            ###
            mod_name = file[:-3] 
            mod = importlib.import_module(f"{Modules_Dir}.{mod_name}")
            if hasattr(mod, "register_arguments") and hasattr(mod, "CATEGORY"):
                category = mod.CATEGORY
                if category not in modules:
                    modules[category] = {}
                modules[category][mod_name] = mod
    return modules

def create_parser():
    parser = argparse.ArgumentParser(description='dynamic module parser', formatter_class=FixedWidthHelpFormatter)
    #parser.add_argument('-v', '--version', action='store_true' ,help='Shows the shencode version')
    #parser.add_argument('--header', type=int, help='Shows a specific banner')
    subparsers = parser.add_subparsers(dest='module', required=True, help='Available modules')

    modules_by_category = load_modules()

    modules_by_category = {k: v for k, v in sorted(modules_by_category.items())}
    for category, modules in modules_by_category.items():
        category_parser = subparsers.add_parser(category, help=f"{category} group", formatter_class=FixedWidthHelpFormatter)
        category_subparsers = category_parser.add_subparsers(dest='command', required=True)

        for mod_name, mod in modules.items():
            mod_parser = category_subparsers.add_parser(mod_name, help=f"Arguments for {mod_name}", formatter_class=FixedWidthHelpFormatter)
            mod.register_arguments(mod_parser)

    return parser

def parse_arguments():
    parser = create_parser()
    arguments = parser.parse_args()
    return arguments