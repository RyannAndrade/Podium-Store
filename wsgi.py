import sys
import os

# Adiciona o diretório do projeto ao PYTHONPATH
path = os.path.dirname(os.path.abspath(__file__))
if path not in sys.path:
    sys.path.append(path)

from app import app as application 