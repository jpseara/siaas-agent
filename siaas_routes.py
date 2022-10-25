from __main__ import app
from flask import jsonify, request, abort
import siaas_aux
import json
import os
import sys

app.config['JSON_AS_ASCII'] = False
app.config['JSON_SORT_KEYS'] = False


@app.route('/', strict_slashes=False)
@app.route('/index', strict_slashes=False)
def index():
    siaas = {
        'name': 'Sistema Inteligente para Automação de Auditorias de Segurança',
        'module': 'Agent',
        'author': 'João Pedro Seara',
        'supervisor': 'Carlos Serrão'
    }
    return jsonify(
        {
            'output': output,
            'status': 'success',
            'total_entries': len(siaas),
            'time': siaas_aux.get_now_utc_str()
        }
    )


@app.route('/siaas-agent', methods=['GET'], strict_slashes=False)
def siaas_agent():
    module = request.args.get('module', default='*', type=str)
    all_existing_modules = "config,neighborhood,platform,portscanner"
    for m in module.split(','):
        if m.lstrip().rstrip() == "*":
            module = all_existing_modules
    output = siaas_aux.merge_module_dicts(module)
    try:
        output["config"]["mongo_pwd"] = '*' * \
            len(output["config"]["mongo_pwd"])
    except:
        pass

    return jsonify(
        {
            'output': output,
            'status': 'success',
            'total_entries': len(output),
            'time': siaas_aux.get_now_utc_str()
        }
    )

