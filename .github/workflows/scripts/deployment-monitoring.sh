#!/bin/bash
# Deployment monitoring and observability integration

# Update Prometheus targets after deployment
update_prometheus_targets() {
    local environment=$1
    local service=$2
    local version=$3
    
    # Generate Prometheus service discovery config
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-targets-$service
  namespace: $environment
data:
  targets.json: |
    [{
      "targets": ["$service-service.$environment.svc.cluster.local:8000"],
      "labels": {
        "service": "$service",
        "environment": "$environment",
        "version": "$version",
        "deployment_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      }
    }]
EOF
}

# Send deployment marker to Grafana
send_grafana_annotation() {
    local environment=$1
    local service=$2
    local version=$3
    local grafana_url=$4
    local grafana_token=$5
    
    curl -X POST "$grafana_url/api/annotations" \
        -H "Authorization: Bearer $grafana_token" \
        -H "Content-Type: application/json" \
        -d "{
            \"dashboardId\": 1,
            \"panelId\": 1,
            \"time\": $(date +%s000),
            \"tags\": [\"deployment\", \"$service\", \"$environment\"],
            \"text\": \"Deployed $service version $version to $environment\"
        }"
}

# Create deployment event in monitoring system
create_deployment_event() {
    local environment=$1
    local service=$2
    local version=$3
    local deployment_type=$4  # canary, rolling, blue-green
    
    kubectl create -f - <<EOF
apiVersion: v1
kind: Event
metadata:
  name: deployment-$service-$version-$(date +%s)
  namespace: $environment
type: Normal
reason: Deployment
message: "Deployed $service version $version using $deployment_type strategy"
involvedObject:
  apiVersion: apps/v1
  kind: Deployment
  name: $service
  namespace: $environment
firstTimestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
lastTimestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
count: 1
source:
  component: github-actions
EOF
}

# Monitor canary metrics
monitor_canary_metrics() {
    local service=$1
    local duration=$2
    local error_threshold=$3
    local latency_threshold=$4
    
    echo "Monitoring canary deployment for $service..."
    
    end_time=$(($(date +%s) + duration))
    
    while [ $(date +%s) -lt $end_time ]; do
        # Check error rate
        error_rate=$(kubectl exec -n production deployment/prometheus -- \
            promtool query instant "rate(http_requests_total{service=\"$service\",version=\"canary\",status=~\"5..\"}[1m]) / rate(http_requests_total{service=\"$service\",version=\"canary\"}[1m])" | \
            jq -r '.data.result[0].value[1] // "0"')
        
        # Check latency
        latency_p99=$(kubectl exec -n production deployment/prometheus -- \
            promtool query instant "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{service=\"$service\",version=\"canary\"}[1m]))" | \
            jq -r '.data.result[0].value[1] // "0"')
        
        echo "$(date): Error rate: $error_rate, P99 latency: ${latency_p99}ms"
        
        # Check thresholds
        if (( $(echo "$error_rate > $error_threshold" | bc -l) )); then
            echo "ERROR: Canary error rate ($error_rate) exceeds threshold ($error_threshold)"
            return 1
        fi
        
        if (( $(echo "$latency_p99 > $latency_threshold" | bc -l) )); then
            echo "ERROR: Canary P99 latency (${latency_p99}ms) exceeds threshold (${latency_threshold}ms)"
            return 1
        fi
        
        sleep 30
    done
    
    echo "Canary metrics within acceptable thresholds"
    return 0
}

# Update service mesh configuration
update_service_mesh() {
    local service=$1
    local canary_weight=$2
    local stable_weight=$3
    
    kubectl patch virtualservice $service -n production --type merge -p "{
        \"spec\": {
            \"http\": [{
                \"match\": [{\"uri\": {\"prefix\": \"/\"}}],
                \"route\": [
                    {
                        \"destination\": {
                            \"host\": \"$service-service\",
                            \"subset\": \"stable\"
                        },
                        \"weight\": $stable_weight
                    },
                    {
                        \"destination\": {
                            \"host\": \"$service-service\",
                            \"subset\": \"canary\"
                        },
                        \"weight\": $canary_weight
                    }
                ]
            }]
        }
    }"
}

# Main command processing
case "$1" in
    "update-prometheus")
        update_prometheus_targets "$2" "$3" "$4"
        ;;
    "grafana-annotation")
        send_grafana_annotation "$2" "$3" "$4" "$5" "$6"
        ;;
    "deployment-event")
        create_deployment_event "$2" "$3" "$4" "$5"
        ;;
    "monitor-canary")
        monitor_canary_metrics "$2" "$3" "$4" "$5"
        ;;
    "update-mesh")
        update_service_mesh "$2" "$3" "$4"
        ;;
    *)
        echo "Usage: $0 {update-prometheus|grafana-annotation|deployment-event|monitor-canary|update-mesh} [args...]"
        exit 1
        ;;
esac