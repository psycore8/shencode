import argparse
import importlib
import os

Modules_Dir = 'modules'

def load_modules():
    modules = {}
    for file in os.listdir(Modules_Dir):
        if file.endswith(".py") and not file.startswith("__"):
            mod_name = file[:-3]  # Entfernt ".py"
            mod = importlib.import_module(f"{Modules_Dir}.{mod_name}")
            if hasattr(mod, "register_arguments") and hasattr(mod, "CATEGORY"):
                category = mod.CATEGORY
                if category not in modules:
                    modules[category] = {}
                modules[category][mod_name] = mod
    return modules

def create_parser():
    parser = argparse.ArgumentParser(description='dynamic module parser')
    #parser.add_argument('-v', '--version', help='Shows the shencode version')
    #parser.add_argument('-b', '--banner', type=int, help='Shows a specified banner')
    subparsers = parser.add_subparsers(dest='module', required=True, help='Available modules')

    modules_by_category = load_modules()

    for category, modules in modules_by_category.items():
        category_parser = subparsers.add_parser(category, help=f"{category} group")
        category_subparsers = category_parser.add_subparsers(dest='command', required=True)

        for mod_name, mod in modules.items():
            mod_parser = category_subparsers.add_parser(mod_name, help=f"Arguments for {mod_name}")
            mod.register_arguments(mod_parser)

    return parser

def parse_arguments():
    parser = create_parser()
    arguments = parser.parse_args()
    return arguments