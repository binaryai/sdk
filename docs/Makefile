# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?=
SPHINXBUILD   ?= poetry run sphinx-build
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile


gettext:
	@$(SPHINXBUILD) -M gettext "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

getpo: gettext
	poetry run sphinx-intl update -p _build/gettext -l zh_CN

en:
	@$(SPHINXBUILD) -D language='en' -b html "$(SOURCEDIR)" "$(BUILDDIR)"/html $(SPHINXOPTS) $(O) 

cn:
	@$(SPHINXBUILD) -D language='zh_CN' -b html "$(SOURCEDIR)" "$(BUILDDIR)"/html/zh_CN $(SPHINXOPTS) $(O) 

all: en cn
	@

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
