
arxiv: compose-arxiv
	pdflatex sd-bls
	bibtex   sd-bls
	pdflatex sd-bls
	pdflatex sd-bls

arxiv-zip: compose-arxiv
	@rm -rf sd-bls-arxiv sd-bls-arxiv.zip && mkdir -p sd-bls-arxiv
	@cp sd-bls.tex sd-bls.bbl arxiv.sty *converted-to.pdf *.eps sd-bls-arxiv
	@zip -r sd-bls-arxiv.zip sd-bls-arxiv/*
# epstopdf verifyrevocations.eps
# epstopdf issueproveverify.eps
# epstopdf hamming.eps

ieee: compose-ieee
	pdflatex sd-bls
	bibtex   sd-bls
	pdflatex sd-bls
	pdflatex sd-bls

compose-ieee:
	@cat sd-bls.head-ieee.tex sd-bls.body.tex > sd-bls.tex

compose-arxiv:
	@cat sd-bls.head-arxiv.tex sd-bls.body.tex > sd-bls.tex

clean:
	rm -f *blg *bbl *dvi *pdf *toc *out *aux *log *lof
	rm -f *converted-to*
	rm -f *.txt *.eps *.png


figures: issueproveverify.eps verifyrevocations.eps pvss.eps

# issueproveverify: ${STATS}
# 	 sed 's/OUT/$@.txt/; s/TERM/pngcairo dashed ${TERMOPTS}/' \
# 	 gnuplot.txt | gnuplot  > $@.png
# 	 sed 's/OUT/$@.txt/; s/TERM/eps/' \
# 	 gnuplot.txt | gnuplot  > $@.eps

# verifyrevocations: ${STATS}
# 	 sed 's/OUT/$@.txt/; s/TERM/pngcairo dashed ${TERMOPTS}/' \
# 	 $@.gnuplot | gnuplot  > $@.png
# 	 sed 's/OUT/$@.txt/; s/TERM/eps/' \
# 	 $@.gnuplot | gnuplot  > $@.eps

%.png: %.txt %.gnuplot
	sed 's/TERM/pngcairo dashed rounded size 1024,768/' \
		$(basename $@).gnuplot | gnuplot  > $(basename $@).png

%.eps: %.txt %.gnuplot
	sed 's/TERM/eps/' \
		$(basename $@).gnuplot | gnuplot  > $(basename $@).eps

%.txt:
	zenroom -l common.lua ${basename $@}.lua | tee $@
