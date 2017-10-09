#!/bin/sh
gnuplot<<EOF
set output "$1.png"
set terminal png
set timefmt "%Y%m%d%H%M"
set multiplot layout 2,1
set xlabel "date"
set xdata time
set format x "%d/%m"
set ylabel "no. updates"
plot '$1' using 1:2 title "number of announced prefixes in time" with lines lc rgb 'blue';
set xlabel "date"
set xdata time
set format x "%d/%m"
set ylabel "no. withdraws"
plot '$1' using 1:3 title "number of withdrawn prefixes in time" with lines lc rgb 'red';
unset multiplot
EOF
