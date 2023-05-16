#!/bin/bash

echo "# POD NetWork Test Result #"

ns="default"

echo "## iperf_tcp_pod_to_pod: ##"
kubectl exec -t -i netperf-client -n ${ns} -- sh -c 'iperf3 -c netperf-headless-svc -t 10' | tail -n 5

echo "## netperf_tcp_rr_pod_to_pod: "
kubectl exec -t -i netperf-client -n ${ns} -- sh -c 'netperf -t TCP_RR -H netperf-headless-svc -p 4444 -l 10' | tail -n 5

echo "## netperf_tcp_crr_pod_to_pod:"
kubectl exec -t -i netperf-client -n ${ns} -- sh -c 'netperf -t TCP_CRR -H netperf-headless-svc -p 4444 -l 10' | tail -n 5
