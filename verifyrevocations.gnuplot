set notitle
set terminal TERM
set key left nobox
set style data points
set autoscale
set xlabel "revocations"
set ylabel "seconds"
plot "verifyrevocations.txt" using 1:2:xticlabels(1) with lines linetype 8 title columnheader
