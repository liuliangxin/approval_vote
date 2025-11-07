go build main.go

n=`cat filesks1.txt|wc -l`
#echo $n
#for i in seq 1 $n-1
while read line
do
	./main $line &
done < filesks1.txt

#echo $(sed -n '1,1p' sks.txt)



