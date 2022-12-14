from __main__ import app
from flask import jsonify, request, abort
import siaas_aux
import json
import os
import sys

app.config['JSON_AS_ASCII'] = False
app.config['JSON_SORT_KEYS'] = False


@app.route('/', strict_slashes=False)
def index():
    output = {
        'name': 'Intelligent System for Automation of Security Audits (SIAAS)',
        'module': 'Agent',
        'author': 'João Pedro Seara',
        'supervisor': 'Carlos Serrão'
    }
    return jsonify(
        {
            'output': output,
            'status': 'success',
            'total_entries': len(output),
            'time': siaas_aux.get_now_utc_str()
        }
    )


@app.route('/siaas-agent', methods=['GET'], strict_slashes=False)
def siaas_agent():
    module = request.args.get('module', default='*', type=str)
    all_existing_modules = "platform,neighborhood,portscanner,config"
    for m in module.split(','):
        if m.lstrip().rstrip() == "*":
            module = all_existing_modules
    output = siaas_aux.merge_module_dicts(module)
    if type(output) == bool and output == False:
        status = "failure"
        output = {}
    else:
        status = "success"
    try:
        for k in output["config"].keys():
            if k.endswith("_pwd") or k.endswith("_passwd") or k.endswith("_password"):
                output["config"][k] = '*' * len(output["config"][k])
    except:
        pass
    return jsonify(
        {
            'output': output,
            'status': status,
            'total_entries': len(output),
            'time': siaas_aux.get_now_utc_str()
        }
    )
