from __main__ import app
from flask import jsonify
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

@app.route('/agent', methods=['GET'])
def agent():
    agent = {}
    try:
        with open(os.path.join(sys.path[0],'tmp/agent.tmp'), 'r') as file:
            content = file.read()
            agent = eval(content)
    except:
        pass
    return jsonify(
        {
            'status': 'success',
            'total_entries': len(agent),
            'time': siaas_aux.get_now_utc_str(),
            'output': agent
        }
    )

@app.route('/neighbourhood', methods=['GET'])
def neighbourhood():
    neigh = {}
    try:
        with open(os.path.join(sys.path[0],'tmp/neighbourhood.tmp'), 'r') as file:
            content = file.read()
            neigh = eval(content)
    except:
        pass
    return jsonify(
        {
            'status': 'success',
            'total_entries': len(neigh),
            'time': siaas_aux.get_now_utc_str(),
            'output': neigh
        }
    )

@app.route('/portscanner', methods=['GET'])
def portscanner():
    portscan = {}
    try:
        with open(os.path.join(sys.path[0],'tmp/portscanner.tmp'), 'r') as file:
           content = file.read()
           portscan = eval(content)
    except:
        pass
    return jsonify(
        {
            'status': 'success',
            'total_entries': len(portscan),
            'time': siaas_aux.get_now_utc_str(),
            'output': portscan
        }
    )
