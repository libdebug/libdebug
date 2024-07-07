import os
import sys
import sphinx


# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'libdebug'
copyright = '2024, Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco'
author = 'JinBlack, Io_no, MrIndeciso, Frank01001'
release = '0.5.2'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.napoleon',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.viewcode',
    'sphinx_code_tabs'
]

templates_path = ['_templates']
exclude_patterns = []

autodoc_default_options = {
    'undoc-members': True,
    'private-members': False, 
    'member-order': 'bysource'
}

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'pydata_sphinx_theme'
html_static_path = ['_static']

# Logging setup
logger = sphinx.util.logging.getLogger(__name__)