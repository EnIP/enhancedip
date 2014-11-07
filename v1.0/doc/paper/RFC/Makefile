# Wed May 28 09:59:01 EDT 2014
GFLAGS = -me
SOURCES = rfcEnIP2014_0618.rof
TBLmkr = /usr/bin/tbl
EQNmkr = /usr/bin/neqn
Fmtr = /usr/bin/groff
TxtFile = rfcEnIP.txt
PDFFile = rfcEnIP.pdf
PSFile = rfcEnIP.ps

pdf: $(SOURCES)
	$(TBLmkr) $(SOURCES) | $(EQNmkr) -Tps | $(Fmtr) $(GFLAGS) | /usr/bin/ps2pdf - $(PDFFile)

orig: rfcEnIPorig.rof
	$(TBLmkr) rfcEnIPorig.rof | $(Fmtr) $(GFLAGS) | /usr/bin/ps2pdf - rfcEnIPorig.pdf

all:
	$(TBLmkr) $(SOURCES) | $(Fmtr) $(GFLAGS) | /usr/bin/ps2pdf - $(PDFFile)
	$(TBLmkr) $(SOURCES) | $(Fmtr) $(GFLAGS) -T ascii | ./noscapes > $(TxtFile)

text: $(SOURCES)
	$(TBLmkr) $(SOURCES) | $(Fmtr) $(GFLAGS) -T ascii | ./noscapes > $(TxtFile)

ps: $(SOURCES)
	$(TBLmkr) $(SOURCES) | $(Fmtr) $(GFLAGS) > $(PSFile)

clean:
	rm -f $(TxtFile) $(PDFFile) $(PSFile)
