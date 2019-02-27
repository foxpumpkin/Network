MAKE := make -C
QUICK := -j8
SRCDIR := src
MAINDIR := main
all: src main

src: FORCE
	@echo " + build libs"
	@$(MAKE) $(SRCDIR) $(QUICK)

main: FORCE
	@echo " + build excutable"
	@$(MAKE) $(MAINDIR) $(QUICK)

clean:
	@echo " + clean up"
	rm -rf lib/*.a *.out*

FORCE:
.FHONY: all clean FORCE
