GHIDRADIR := ${HOME}/ghidra_12.0.4_PUBLIC
PROCDIR := $(GHIDRADIR)/Ghidra/Processors/h8
#DEBUGARGS := -x -u -l -n -t -c -f -o
DEBUGARGS := 
SLEIGHARGS := $(DEBUGARGS) -a
#SLEIGHARGS := $(DEBUGARGS) h8520

build:
	sleigh $(SLEIGHARGS) $$PWD

install:
	mkdir -p $(PROCDIR)/data/languages
	rsync -av --delete --exclude='*.xml' $$PWD $(PROCDIR)/data/languages
	mkdir -p $(PROCDIR)/data/patterns
	cp pattern*.xml $(PROCDIR)/data/patterns/
	touch $(PROCDIR)/Module.manifest
	echo $(SLEIGHARGS) > $(PROCDIR)/data/sleighArgs.txt
