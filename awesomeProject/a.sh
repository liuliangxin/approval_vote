# go build main.go

# n=`cat filesks1.txt|wc -l`
# #echo $n
# #for i in seq 1 $n-1
# while read line
# do
# 	./main $line &
# done < filesks1.txt

#echo $(sed -n '1,1p' sks.txt)
go build main.go
mkdir -p logs

# 记录前 5 个节点的目录清单
: > logs/first5_nodes.txt

count=0
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"                 # 去掉可能的 \r
  [[ -z "$line" ]] && continue         # 跳过空行
  [[ "$line" =~ ^[[:space:]]*# ]] && continue  # 跳过注释行

  ((count++))
  echo "[node] start $line"

  if ((count <= 5)); then
    # 记录前 5 个节点的“目录/ID”
    echo "$line" >> logs/first5_nodes.txt

    # 作为文件名用 basename，避免路径里有斜杠产生子目录
    base="$(basename "$line")"
    nohup ./main "$line" >> "logs/${count}_${base}.log" 2>&1 &
    
  else
    # 其余节点正常启动，但不写日志
    nohup ./main "$line" >/dev/null 2>&1 &
    
  fi
done < filesks1.txt
wait

#!/usr/bin/env bash
# set -euo pipefail

# # 本次运行的唯一ID（UTC时间戳）
# run_id="$(date -u +'%Y%m%dT%H%M%SZ')"
# mkdir -p "logs/${run_id}"

# # 记录前 5 个节点的目录清单（本次运行）
# : > "logs/${run_id}/first5_nodes.txt"

# count=0
# while IFS= read -r line || [[ -n "$line" ]]; do
#   line="${line%$'\r'}"                        # 去掉可能的 \r
#   [[ -z "$line" ]] && continue                # 跳过空行
#   [[ "$line" =~ ^[[:space:]]*# ]] && continue # 跳过注释行

#   ((count++))
#   echo "[node] start $line"

#   base="$(basename "$line")"

#   if ((count <= 5)); then
#     echo "$line" >> "logs/${run_id}/first5_nodes.txt"

#     # 节点级时间戳（带毫秒；GNU date 支持 %3N。若系统不支持可改用 %s）
#     ts_node="$(date +'%Y%m%d_%H%M%S')"
#     nohup ./main "$line" > /dev/null 2>&1 &
#     pid=$!

#     # 最终日志文件名：序号_节点名_时间戳_PID.log
#     log_file="logs/${run_id}/${count}_${base}_${ts_node}_${pid}.log"

#     # 把该后台进程的输出重定向到独立文件（用 /proc/$pid/fd/1/2 不如用重启方式简单，
#     # 因此我们改为先起再用重定向不可行；更简单是直接在 nohup 时就定好文件：）
#     # 重新以带日志文件的方式启动
#     kill "$pid" 2>/dev/null || true
#     nohup ./main "$line" >> "$log_file" 2>&1 &

#   else
#     nohup ./main "$line" >/dev/null 2>&1 &
#   fi
# done < filesks1.txt

# wait
# echo "logs saved under logs/${run_id}"

