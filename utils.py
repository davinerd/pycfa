from colorama import Fore, Back, Style
import pprint
from termcolor import cprint
from pyfiglet import figlet_format
from datetime import datetime
from cfn_flip import to_json
import petname  # because, you know...fun


def print_error(msg):
    print("[X] " + Fore.RED + msg + Fore.RESET)


def print_warning(msg):
    print("[!] " + Fore.YELLOW + msg + Fore.RESET)


def print_success(msg):
    print("[*] " + Fore.GREEN + msg + Fore.RESET)


def print_banner(v):
    cprint(figlet_format('pycfa', font='starwars'), 'green')
    print "version " + v
    print "by Davide Barbato"
    print "@DavBarbato"
    print "=" * 20


def print_audit_msg(msg, lvl):
    bgcolor = Back.LIGHTBLUE_EX
    txtcolor = Fore.LIGHTBLUE_EX
    if lvl == "danger":
        bgcolor = Back.RED
        txtcolor = Fore.RED
    elif lvl == "warning":
        bgcolor = Back.YELLOW
        txtcolor = Fore.YELLOW

    print(bgcolor + Fore.BLACK + lvl + Style.RESET_ALL + txtcolor + " " + msg + Style.RESET_ALL)


def print_audit(report):
    for audit in report:
        print_success("{0} ({1})".format(audit['ResourceName'], audit['ResourceType']))
        for alert in audit['Alerts']:
            print_audit_msg(alert['Description'], alert['Level'])
            print alert['Trigger']
        print "=" * 10


def print_report(data):
    for item in data:
        print_audit(item['Report'])


def print_json(data):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(data)


def cf_to_json(data):
    return to_json(data)


def report_to_json(data):
    report = dict()
    report['Name'] = "pycfa report :: {0}".format(petname.Generate())
    report['Timestamp'] = datetime.utcnow().isoformat()
    report['Data'] = data

    return report
