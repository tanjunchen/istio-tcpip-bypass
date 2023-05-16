#!/bin/bash

echo "# POD NetWork Test Result"
echo "## iperf_tcp_pod_to_pod: "
kubectl exec -t -i netperf-client -n network-bench -- sh -c 'iperf3 -c netperf-headless-svc -t 10' | tail -n 5

echo "## iperf_udp_pod_to_pod: "
kubectl exec -t -i netperf-client -n network-bench -- sh -c 'iperf3 -u -c netperf-headless-svc -t 10' | tail -n 5

echo "## netperf_tcp_rr_pod_to_pod: "
kubectl exec -t -i netperf-client -n network-bench -- sh -c 'netperf -t TCP_RR -H netperf-headless-svc -p 4444 -l 10' | tail -n 5

echo "## netperf_tcp_crr_pod_to_pod:"
kubectl exec -t -i netperf-client -n network-bench -- sh -c 'netperf -t TCP_CRR -H netperf-headless-svc -p 4444 -l 10' | tail -n 5

netperf_pod=`kubectl  get pods -n network-bench | grep deploy | awk  '{print $1}'`

echo "## iperf_tcp_pod_to_pod_over_node:"
kubectl exec -t -i ${netperf_pod} -n network-bench -- sh -c 'iperf3 -c netperf-headless-svc -t 10' | tail -n 5

echo "## iperf_udp_pod_to_pod_over_node"
kubectl exec -t -i ${netperf_pod} -n network-bench -- sh -c 'iperf3 -u -c netperf-headless-svc -t 10' | tail -n 5

echo "## netperf_tcp_rr_pod_to_pod_over_node: "
kubectl exec -t -i ${netperf_pod} -n network-bench -- sh -c 'netperf -t TCP_RR -H netperf-headless-svc -p 4444 -l 10' | tail -n 5

echo "## netperf_tcp_crr_pod_to_pod_over_node:"
kubectl exec -t -i ${netperf_pod} -n network-bench -- sh -c 'netperf -t TCP_CRR -H netperf-headless-svc -p 4444 -l 10' | tail -n 5

echo "## iperf3_tcp_pod_to_remote_svc"
kubectl exec -t -i netperf-client -n network-bench -- sh -c 'iperf3 -c netperf-remote-svc -t 10'  | tail -n 6

echo "## iperf3_udp_pod_to_remote_svc"
kubectl exec -t -i netperf-client -n network-bench -- sh -c 'iperf3 -u -c netperf-remote-svc -t 10' | tail -n 6

echo "## netperf_tcp_rr_pod_to_remote_svc"
kubectl exec -t -i netperf-client -n network-bench -- sh -c 'netperf -t TCP_RR -H netperf-remote-svc -p 4444 -l 10' | tail -n 6

echo "## netperf_tcp_crr_pod_to_remote_svc"
kubectl exec -t -i netperf-client -n network-bench -- sh -c 'netperf -t TCP_CRR -H netperf-remote-svc -p 4444 -l 10' | tail -n 6
