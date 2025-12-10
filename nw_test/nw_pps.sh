#!/bin/bash

INTERFACE=${1:-ens11}
DURATION=20
VERBOSE=0

# 参数解析
for arg in "$@"; do
    if [[ "$arg" == "-v" ]]; then
        VERBOSE=1
    elif [[ "$arg" =~ ^[0-9]+$ ]]; then
        DURATION=$arg
    elif [[ "$arg" != "$INTERFACE" ]]; then
        INTERFACE=$arg
    fi
done

echo "采集网卡: $INTERFACE, 时长: ${DURATION}秒"

sar -n DEV 1 $DURATION | awk -v intf="$INTERFACE" -v verbose=$VERBOSE '
BEGIN { count=0; sum=0; min=999999; max=0 }
/^[0-9]{2}:[0-9]{2}:[0-9]{2} (AM|PM)/ && $3 == intf {
    pps = $4 + 0
    count++
    sum += pps
    if (pps > max) max = pps
    if (pps < min) min = pps
    if (verbose == 1) print "时间: " $1 " " $2 ", PPS: " pps
}
END {
    if (count > 0) {
        print "最大 PPS: " max
        print "最小 PPS: " min
        print "平均 PPS: " sum/count
    } else {
        print "未找到数据"
    }
}'