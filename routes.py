from __main__ import app
from flask import jsonify, request, abort
import siaas_aux
import json
import os
import sys

app.config['JSON_AS_ASCII'] = False


@app.route('/')
@app.route('/index')
def index():
    siaas = {
        'name': 'Sistema Inteligente para Automação de Auditorias de Segurança',
        'module': 'Agent',
        'author': 'João Pedro Seara',
        'supervisor': 'Carlos Serrão'
    }
    return jsonify(
        {
            'status': 'success',
            'total_entries': len(siaas),
            'time': siaas_aux.get_now_utc_str(),
            'output': siaas
        }
    )


@app.route('/siaas-agent', methods=['GET'])
def siaas_agent():
    module = request.args.get('module', default='*', type=str)
    module_list = module.split(',')
    all_existing_modules = ["agent", "config", "neighbourhood", "portscanner"]
    if "*" in module_list:
        module_list = all_existing_modules
    output = siaas_aux.merge_module_dicts(module_list)
    try:
        output["config"]["mongo_pwd"] = '*' * \
            len(output["config"]["mongo_pwd"])
    except:
        pass
    return jsonify(
        {
            'status': 'success',
            'total_entries': len(output),
            'time': siaas_aux.get_now_utc_str(),
            'output': output
        }
    )
