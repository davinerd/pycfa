import json
import os
from utils import print_error, print_success
import re


class CFAudit:
    rules_file = os.path.join(os.path.dirname(__file__), "rules/rules.json")
    rules = None

    def __init__(self, custom_rule=None):
        if custom_rule:
            self.rules_file = custom_rule

        if not self.__check_rules():
            raise Exception

        with open(self.rules_file, 'r') as f:
            data = f.read()

        self.rules = json.loads(data)

    def __check_rules(self):
        if not os.path.exists(self.rules_file):
            print_error(self.rules_file + " does not exist! Check the path and retry")
            return False

        if not os.path.isfile(self.rules_file):
            print_error(self.rules_file + " is not a regular file!")
            return False

        return True

    def __find_and_replace_ref(self, res, params):
        if type(res) is int:
            return res

        if type(res) is bool:
            return res

        if "Ref" in res:
            ref = res.values()[0]
            if ref in params.keys():
                if 'Value' in params[ref]:
                    res = params[ref]['Value']
                else:
                    return params[ref]
        else:
            if type(res) is dict:
                for k, v in res.iteritems():
                    res[k] = self.__find_and_replace_ref(v, params)
            elif type(res) is list:
                for index, item in enumerate(res):
                    res[index] = self.__find_and_replace_ref(item, params)

        return res

    @staticmethod
    def __dict_compare(d1, d2):
        d1_keys = set(d1.keys())
        d2_keys = set(d2.keys())
        intersect_keys = d1_keys.intersection(d2_keys)
        same = set(o for o in intersect_keys if d1[o] == d2[o])
        return same

    def audit(self, resources, params=None):
        audit_results = list()

        for k, v in resources.items():
            audit_result = dict()
            audit_result['Alerts'] = list()

            print_success("Auditing resource " + k)
            audit_result['ResourceName'] = k

            res_type = v['Type']
            audit_result['ResourceType'] = res_type

            if 'Properties' in v:
                res_prop = v['Properties']

            # adding an extra field
            res_prop.update({'ResourceName': k})

            for i, z in res_prop.items():
                res_prop[i] = self.__find_and_replace_ref(z, params)

            # didn't find a way to optimise the following piece of code...
            for rule in self.rules:
                rules = rule['rules']

                for single_rule in rules:
                    if 'key' in single_rule:
                        findings = FindKey(res_prop).get(single_rule['key'])
                    else:
                        findings = res_prop

                    if not findings:
                        continue

                    # avoid situation where we have [[{k:v}]]
                    if isinstance(findings, list) and len(findings) == 1:
                        findings = findings[0]

                    if isinstance(findings, dict):
                        findings = [findings]

                    # we may want to discard unrelated resources
                    if 'type' in single_rule and single_rule['type'] != res_type:
                        continue

                    if single_rule['match'] == "bool":
                        audit_result['Alerts'].append(
                            {'Level': rule['level'], 'Description': rule['description'], 'Trigger': single_rule['key']})
                        continue

                    for entry in findings:
                        actual_rule = {i: single_rule[i] for i in single_rule if i != 'match' and i != 'key'}
                        if isinstance(entry, dict):
                            entries = [entry]
                            for event in entries:
                                if single_rule['match'] == "strict" and self.__dict_compare(event, actual_rule):
                                    audit_result['Alerts'].append(
                                        {'Level': rule['level'], 'Description': rule['description'],
                                         'Trigger': event})
                                elif single_rule['match'] == "regex":
                                    if actual_rule.keys()[0] in event.keys():
                                        values = event[actual_rule.keys()[0]]
                                        # in case we have e.g. 'Actions': ['a:*', 'b:1', 'c:2']
                                        if isinstance(values, list):
                                            for row in values:
                                                result = re.match(actual_rule.values()[0], row)
                                                if result:
                                                    audit_result['Alerts'].append(
                                                        {'Level': rule['level'], 'Description': rule['description'],
                                                         'Trigger': entry})
                                        else:
                                            result = re.match(actual_rule.values()[0], values)
                                            if result:
                                                audit_result['Alerts'].append(
                                                    {'Level': rule['level'], 'Description': rule['description'],
                                                     'Trigger': entry})

            if audit_result['Alerts']:
                audit_results.append(audit_result)

        return audit_results

    def audit_ok(self, resources, params=None):
        audit_results = list()

        for k, v in resources.items():
            audit_result = dict()
            audit_result['Alerts'] = list()

            print_success("Auditing resource " + k)
            audit_result['ResourceName'] = k

            res_type = v['Type']
            audit_result['ResourceType'] = res_type

            if 'Properties' in v:
                res_prop = v['Properties']

            # adding an extra field
            res_prop.update({'ResourceName': k})

            for i, z in res_prop.items():
                res_prop[i] = self.__find_and_replace_ref(z, params)

            # didn't find a way to optimise the following piece of code...
            for rule in self.rules:
                if res_type == rule['type']:

                    if 'key' in rule:
                        findings = FindKey(res_prop).get(rule['key'])
                    else:
                        findings = res_prop

                    if not findings:
                        continue

                    # avoid situation where we have [[{k:v}]]
                    if isinstance(findings, list) and len(findings) == 1:
                        findings = findings[0]

                    if isinstance(findings, dict):
                        findings = [findings]

                    if rule['match'] == "bool":
                        audit_result['Alerts'].append(
                            {'Level': rule['level'], 'Description': rule['description'], 'Trigger': rule['key']})
                        continue

                    for entry in findings:
                        for myrule in rule['rules']:
                            if isinstance(entry, dict):
                                entries = [entry]
                                for event in entries:
                                    if rule['match'] == "strict" and self.__dict_compare(event, myrule):
                                        audit_result['Alerts'].append(
                                            {'Level': rule['level'], 'Description': rule['description'],
                                             'Trigger': event})
                                    elif rule['match'] == "regex":
                                        if myrule.keys()[0] in event.keys():
                                            values = event[myrule.keys()[0]]

                                            # in case we have e.g. 'Actions': ['a:*', 'b:1', 'c:2']
                                            if isinstance(values, list):
                                                for row in values:
                                                    result = re.match(myrule.values()[0], row)
                                                    if result:
                                                        audit_result['Alerts'].append(
                                                            {'Level': rule['level'], 'Description': rule['description'],
                                                             'Trigger': entry})
                                                        # break
                                            else:
                                                result = re.match(myrule.values()[0], values)
                                                if result:
                                                    audit_result['Alerts'].append(
                                                        {'Level': rule['level'], 'Description': rule['description'],
                                                         'Trigger': entry})
                                                    # break

            if audit_result['Alerts']:
                audit_results.append(audit_result)

        return audit_results


class FindKey(dict):
    def get(self, path, default=None):
        keys = path.split(".")
        val = None

        for key in keys:
            if val:
                if isinstance(val, list):
                    val = [v.get(key, default) if v else None for v in val]
                else:
                    val = val.get(key, default)
            else:
                val = dict.get(self, key, default)

            if not val:
                break

        return val
