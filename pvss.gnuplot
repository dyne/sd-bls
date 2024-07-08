set notitle
set terminal TERM
set key left nobox
set style data points
set autoscale
set xlabel "shares"
set ylabel "seconds"
# plot "pvss.txt" using 1:2:xticlabels(1) with lines linetype 8 title columnheader
plot for [col=2:4] "pvss.txt" using 0:col:xticlabels(1) with lines linetype 8 dashtype col title columnheader
