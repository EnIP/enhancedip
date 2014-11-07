all: main

#this make command requires a bit of explanation.
#main.tex pulls in all the required files and generates main.aux
#the first time main.aux is generated it has no bibliography references
#we run the bibtex command and then latex twice on main.tex to generate
#a main.dvi file that has the bibliography.  Finally, we use dvipdf to 
#create a main.pdf file that contains the paper.
main:
	latex main.tex
	bibtex main.aux
	latex main.tex
	latex main.tex
	dvipdf main.dvi

display:
	xpdf main.pdf

clean:
	rm -f *.backup *.bbl *.blg *.pdf *.log *.aux *.dvi main.tex~ refs.bib~ 
	rm -f ourrefs.bib~ ip_options.tex~ transitions.tex~
