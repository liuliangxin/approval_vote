










go build main.go
mkdir -p logs


: > logs/first5_nodes.txt

count=0
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"                 
  [[ -z "$line" ]] && continue         
  [[ "$line" =~ ^[[:space:]]*

  ((count++))
  echo "[node] start $line"

  if ((count <= 5)); then
    
    echo "$line" >> logs/first5_nodes.txt

    
    base="$(basename "$line")"
    nohup ./main "$line" >> "logs/${count}_${base}.log" 2>&1 &
    
  else
    
    nohup ./main "$line" >/dev/null 2>&1 &
    
  fi
done < filesks1.txt
wait















































