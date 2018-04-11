import os
import sys
import argparse
import json
from utils import *
from CFAudit.cfaudit import CFAudit
from timeit import default_timer as timer

VERSION = "0.1"

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument("-d", "--dir", help="specify a directory", action="store", dest="dirpath")
group.add_argument("-f", "--file", help="a CF template file", action="store", dest="cftemplate")
parser.add_argument("-p", "--parameters", help="parameters file for the CF template", action="store", dest="cfparams")
parser.add_argument("-r", "--rules", help="specify a custom rule file", action="store", dest="custom_rule")
parser.add_argument("-j", "--json", help="output in JSON format", action="store_true")

# initialised in main()
cf = None


def replace_params(params, subs):
    for s in subs:
        name = s['ParameterKey']
        if name in params:
            params[name]['Value'] = s['ParameterValue']


def audit_cf(data, cfparams=None):
    params = None
    mapping = None

    if 'Parameters' in data:
        params = data['Parameters']

    if 'Mappings' in data:
        # TODO Implemetare il mapping come se fosse cfparams
        mapping = data['Mappings']

    resources = data['Resources']

    if cfparams and params:
        replace_params(params, cfparams)

    report = cf.audit(resources, params)

    return report


def parse_cftemplate(cfile, cfparams=None):
    content_params = None

    with open(cfile, 'r') as f:
        content = f.read()

    if cfparams:
        with open(cfparams, 'r') as p:
            content_params = p.read()

    try:
        parsed_data = json.loads(cf_to_json(content))

        if content_params:
            try:
                content_params = json.loads(cf_to_json(content_params))
            except Exception as e:
                print_error(cfparams + ": " + str(e))
                return 1
    except Exception as e:
        print_error(cfile + ": " + str(e))
        return 1

    if cfparams:
        cfparams = os.path.basename(cfparams)

    return {'FileName': os.path.basename(cfile), 'Report': audit_cf(parsed_data, content_params),
            'ParameterFile': cfparams}


def parse_cfdir(dirpath, cfparams=None):
    report = list()

    for d in os.listdir(dirpath):
        if cfparams is not None and d == cfparams:
            continue

        full_path = os.path.join(dirpath, d)
        if os.path.isfile(full_path):
            print_success("Parsing file " + d)
            results = parse_cftemplate(full_path, cfparams)
            report.append(results)

    return report


def main():
    results = None

    args = parser.parse_args()

    global cf
    cf = CFAudit(args.custom_rule)

    print_banner(VERSION)

    if not args.cftemplate and not args.dirpath:
        parser.print_help()
        return 1

    if args.cfparams:
        if not os.path.exists(args.cfparams):
            print_error(args.cfparams + " not found!")
            return 1

        if not os.path.isfile(args.cfparams):
            print_error(args.cfparams + " is not a file!")
            return 1

    if args.cftemplate:
        if not os.path.exists(args.cftemplate):
            print_error(args.cftemplate + " not found!")
            return 1
        elif not os.path.isfile(args.cftemplate):
            print_error(args.cftemplate + " is not a file!")
            return 1
        else:
            results = [parse_cftemplate(args.cftemplate, args.cfparams)]

    elif args.dirpath:
        if not os.path.exists(args.dirpath):
            print_error(args.dirpath + " not found!")
            return 1
        elif not os.path.isdir(args.dirpath):
            print_error(args.dirpath + " is not a dir!")
            return 1
        else:
            results = parse_cfdir(args.dirpath, args.cfparams)

    print "=== Output Report Audit ==="
    if args.json:
        print_json(report_to_json(results))
    else:
        print_report(results)


if __name__ == '__main__':
    #start = timer()
    sys.exit(main())
    #main()
    #end = timer()
    #print(end - start)
