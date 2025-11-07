#! /bin/bash 
proname='./main'
process=`ps -ef|grep $proname|grep -v grep|grep -v PPID|awk '{print $2}'`
for i in $process
   do
   echo "kill main"
   kill -9 $i
done
