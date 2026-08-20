#!/usr/bin/env bash
# Monitor the running dual-arm effect evaluation tasks.
# Usage: watch -n 30 bash scripts/monitor-v2-effect.sh
#   or:  bash scripts/monitor-v2-effect.sh   (one-shot)

REPORTS=/home/today/dev/agent-guard/reports

count_cases() { ls "$1" 2>/dev/null | grep -c '^[A-Z]'; }

echo "=== $(date '+%H:%M:%S') ==="

echo "--- 进程 ---"
alive=0
for pid in 167486 191246 205334; do
    if kill -0 "$pid" 2>/dev/null; then
        echo "  $pid: 运行中 ($(ps -p "$pid" -o etime= | tr -d ' '))"
        alive=$((alive + 1))
    fi
done
[ "$alive" -eq 0 ] && echo "  全部进程已结束"

echo "--- 进度 ---"
# a0: oldest scratch dir = legacy serial arm; the rest = parallel shards
a0_dirs=$(for d in /tmp/agentguard-competition-a0-*/results/*/cases; do
    echo "$(stat -c %W "$d") $d"
done | sort -n | awk '{print $2}')
if [ -n "$a0_dirs" ]; then
    oldest=$(echo "$a0_dirs" | head -1)
    echo "  旧A0串行: $(count_cases "$oldest")/70"
    total=0
    for d in $(echo "$a0_dirs" | tail -n +2); do
        total=$((total + $(count_cases "$d")))
    done
    [ "$total" -gt 0 ] && echo "  新A0并行: ~$total/70 (已完成分片已清理)"
fi
total=0
for d in /tmp/agentguard-competition-a4-*/results/*/cases; do
    total=$((total + $(count_cases "$d")))
done
[ "$total" -gt 0 ] && echo "  新A4并行: $total/70"

echo "--- 落盘 ---"
for name in v2-effect-full v2-effect-a0-parallel v2-effect-a4-parallel; do
    if [ -f "$REPORTS/$name/effect-report.json" ]; then
        echo "  $name: ✅ 已完成"
    elif [ -f "$REPORTS/$name/effect-failure.json" ]; then
        echo "  $name: ❌ 失败 (effect-failure.json)"
    fi
done

echo "--- 错误 ---"
found=0
for log in "$REPORTS"/v2-effect-*.log; do
    [ -f "$log" ] || continue
    err=$(grep -iE "error|409|429|exception|FAILED|Traceback" "$log" | tail -1)
    if [ -n "$err" ]; then
        echo "  $(basename "$log"): $err"
        found=1
    fi
done
[ "$found" -eq 0 ] && echo "  无错误"
