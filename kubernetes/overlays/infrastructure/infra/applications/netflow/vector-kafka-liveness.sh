#!/bin/sh
# Liveness probe for the Vector pods that produce to Kafka (eve-receiver, hubble-shipper).
# Mounted from ConfigMap vector-kafka-liveness.
#
# After the broker restarts, Vector's Kafka producer can stay wedged on a stale "no leader"
# partition and drop every event (MessageTimedOut) until the pod restarts. Fails when the
# Kafka sinks' unintentional drops went up since the last probe. The counter is kept in the
# pod's emptyDir, so it survives a container restart; the fresh counter then reads lower and
# passes.
state=/var/lib/vector/kafka-dropped
metrics=$(wget -qO- -T 5 http://REDACTED_IP:9598/metrics) || exit 1
dropped=$(printf '%s\n' "$metrics" | awk '
  /^vector_component_discarded_events_total\{/ && /component_type="kafka"/ && /intentional="false"/ { s += $2 }
  END { printf "%d\n", s }')
prev=$(cat "$state" 2>/dev/null || echo 0)
echo "$dropped" > "$state"
if [ "$dropped" -gt "$prev" ]; then
  echo "Kafka sinks dropped $((dropped - prev)) events since the last probe"
  exit 1
fi
