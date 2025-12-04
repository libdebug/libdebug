__version__ = '0.5.5'

from docutils.parsers.rst import directives
from docutils import nodes
from sphinx.directives.code import CodeBlock
from sphinx.util.docutils import SphinxDirective
from sphinx.util.fileutil import copy_asset_file

import os

try:
    from sphinx.util.texescape import escape as latex_escape
except ImportError:     # ancient sphinx:
    from sphinx.util.texescape import tex_escape_map

    def latex_escape(s, latex_engine):
        return s.translate(tex_escape_map)


CSS_FILE = "code-tabs.css"
JS_FILE = "code-tabs.js"
STY_FILE = "tabenv.sty"

_html_builders = [
    "html",
    "singlehtml",
    "dirhtml",
    "readthedocs",
    "readthedocsdirhtml",
    "readthedocssinglehtml",
    "readthedocssinglehtmllocalmedia",
    "spelling",
]

_latex_builders = [
    "latex",
]


class TabsNode(nodes.container): pass
class TabNode(nodes.container): pass
class TabBarNode(nodes.Part, nodes.Element): pass
class TabButtonNode(nodes.Part, nodes.Element): pass


class TabsDirective(SphinxDirective):

    """
    This directive is used to contain a group of code blocks which can be
    selected as tabs of a single notebook.
    """

    final_argument_whitespace = True
    required_arguments = 0
    optional_arguments = 1
    has_content = True

    def run(self):
        self.assert_has_content()

        node = TabsNode()
        node["classes"].append("tabs")
        node["tabgroup"] = self.arguments[0] if self.arguments else None

        self.add_name(node)
        self.state.nested_parse(self.content, self.content_offset, node)

        # Generate navbar:
        if self.env.app.builder.name in _html_builders:
            tabbar = TabBarNode()
            tabbar["classes"].append("tabbar")

            selected = 0
            for i, tab in enumerate(node.children):
                button = TabButtonNode()
                button['classes'].append('tabbutton')
                button['tabid'] = i
                button.append(nodes.Text(tab["tabname"]))
                tabbar.append(button)
                if tab.get('selected'):
                    selected = i

            tabbar.children[selected]['classes'].append('selected')
            node.children[selected]['classes'].append('selected')
            node.insert(0, tabbar)

        return [node]


class TabDirective(SphinxDirective):

    option_spec = {
        'selected': directives.flag,
    }

    final_argument_whitespace = True
    required_arguments = 1
    optional_arguments = 0
    has_content = True

    def run(self):
        index = len(self.state.parent.children)

        title = self.options.get('title')
        if not title:
            title = self.options.get('caption')
        if not title and self.arguments:
            title = self.arguments[0]
        if not title:
            title = "Tab {}".format(index + 1)

        node = TabNode()
        node['tabid'] = index
        node['tabname'] = title
        node['selected'] = 'selected' in self.options
        node['classes'].append('tab')
        node += self.make_page(node)

        return [node]

    def make_page(self, node):
        node['classes'].append("texttab")
        page = nodes.container()
        self.state.nested_parse(self.content, self.content_offset, page)
        return page


class CodeTabDirective(CodeBlock):

    """Single code-block tab inside .. code-tabs."""

    option_spec = CodeBlock.option_spec.copy()
    option_spec.update({
        'title': directives.unchanged,
        'selected': directives.flag,
    })

    run = TabDirective.run

    def make_page(self, node):
        node['classes'].append("codetab")
        if self.env.app.builder.name in _html_builders:
            self.options.pop('caption', None)
        else:
            self.options.setdefault('caption', node['tabname'])
        return super().run()


def visit_tabgroup_html(self, node):
    self.body.append(self.starttag(node, 'div', **{
        'data-tabgroup': node['tabgroup'] or '',
        'class': 'docutils container',
    }))


def depart_tabgroup_html(self, node):
    self.body.append('</div>')


def visit_tabbar_html(self, node):
    self.body.append(self.starttag(node, 'ul'))


def depart_tabbar_html(self, node):
    self.body.append('</ul>')


def visit_tabbutton_html(self, node):
    self.body.append(self.starttag(node, 'li', **{
        'data-id': node['tabid'],
        'onclick': "sphinx_code_tabs_onclick(this)",
    }))


def depart_tabbutton_html(self, node):
    self.body.append('</li>')


def visit_tab_html(self, node):
    self.body.append(self.starttag(node, 'div', **{
        'data-id': node['tabid'],
    }))


def depart_tab_html(self, node):
    self.body.append('</div>')


def visit_tab_latex(self, node):
    if 'texttab' in node['classes']:
        self.body.append(r'\sphinxSetupCaptionForVerbatim{{{}}}'.format(
            latex_escape(node['tabname'], self.config.latex_engine),
        ))
        self.body.append(r'\begin{tab}')


def depart_tab_latex(self, node):
    if 'texttab' in node['classes']:
        self.body.append(r'\end{tab}')


def add_assets(app):
    package_dir = os.path.dirname(__file__)
    app.config.html_static_path.append(package_dir)
    app.add_css_file(CSS_FILE)
    app.add_js_file(JS_FILE)
    if app.builder.name in _latex_builders:
        copy_asset_file(
            os.path.join(package_dir, STY_FILE),
            app.builder.outdir)
        app.add_latex_package('tabenv')


def setup(app):
    app.add_node(TabsNode, html=(visit_tabgroup_html, depart_tabgroup_html))
    app.add_node(TabBarNode, html=(visit_tabbar_html, depart_tabbar_html))
    app.add_node(
        TabButtonNode,
        html=(visit_tabbutton_html, depart_tabbutton_html))
    app.add_node(
        TabNode,
        html=(visit_tab_html, depart_tab_html),
        latex=(visit_tab_latex, depart_tab_latex))
    app.add_directive("tabs", TabsDirective)
    app.add_directive("tab", TabDirective)
    app.add_directive("code-tabs", TabsDirective)
    app.add_directive("code-tab", CodeTabDirective)
    app.connect("builder-inited", add_assets)

    return {
        "version": __version__,
        "parallel_read_safe": True,
    }
