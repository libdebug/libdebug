make clean
sphinx-autogen -o source/_autosummary source/index.rst
sphinx-apidoc -o source/ ../
make html
cp build/html/_static/favicon.ico build/html/favicon.ico