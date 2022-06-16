import os
import IPython
from warnings import *
from ses_fonctions import *
from traitlets.config import Config
from traitlets import Unicode

c=Config()
#c.TerminalInteractiveShell.prompt_in1='>>>'
#c.InteractiveShellApp.
c.TerminalIPythonApp.display_banner = False
c.InteractiveShell.automagic= False #desactiver le code magic dans le terminal
#c.InteractiveShellApp.file_to_run='scanner/ses_fonctions.py' #executé un fichier
"""c.InteractiveShellApp.exec_lines = [
    'print("\\n Bienvenu sur Recon \\n")',
]
"""
warn("InteractiveShell.{name}")

print(dir(c.TerminalInteractiveShell))
c.TerminalInteractiveShell.prompt_in1='>>>'

#c.TerminalInteractiveShell.prompt_in1=Unicode('In [\\#]: ').tag(config=True)
#print(c)
# Now we start ipython with our configuration
#TerminalInteractiveShell

import IPython
IPython.start_ipython(config=c)
