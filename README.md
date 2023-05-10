# TCP/IP Bypass with eBPF in Istio

This solution aims to bypass TCP/IP stack to accelerate service mesh, it benefits two scenarios:

* p2p communication with sidecar injected
* p2p communication without sidecar injected

This solution is totally independent, which

* does not require changes to linux kernel
* does not require changes to Istio and Envoy (>= v1.10)
* does not require changes to CNI plugin

15%~20% latency decrease is expected for p2p communication on the same host.

## System Requirements

* Minimal: Distribution with kernel version >= 4.18
* Optimal: Ubuntu 20.04 with Linux 5.4.0-74-generic

Build Docker Image and Load eBPF Program

Build docker image

    $ docker build --network=host -t ${IMAGE_NAME} .

Load eBPF program via docker command

    $ docker run --mount type=bind,source=/sys/fs,target=/sys/fs,bind-propagation=rshared --privileged --name tcpip-bypass  ${IMAGE_NAME}

Load eBPF program via setting up a deamonset

    $ kubectl apply -f bypass-tcpip-daemonset.yaml

Unload eBPF program via destroying Docker container or deamonset

## Debug Log

Enable debug log via modifying the debug MAP

    $ sudo bpftool map update name debug_map key hex 0 0 0 0  value hex 1 0 0 0

Read log from kernel tracepipe

    $ sudo cat /sys/kernel/debug/tracing/trace_pipe

## 本地调试

构建 tcp-ip-pass 编译工具：
```
docker build --platform=linux/amd64 -t docker.io/tanjunchen/tcp-ip-pass-tool:test -f Dockerfile.build_tool .  
docker push docker.io/tanjunchen/tcp-ip-pass-tool:test
```

构建 tcp-ip-pass 镜像：
```
docker build --platform=linux/amd64  --network=host -t registry.baidubce.com/csm/ebpf-tanjunchen:test  -f Dockerfile.local  .
docker push registry.baidubce.com/csm/ebpf-tanjunchen:test
```

请求测试：
```
kubectl  exec deployments/wrk -it -- curl -sI 172.16.27.36
```

开启内核 debug 日志：
```
开启：
sudo bpftool map update id 65(debug_map id)  key hex 0 0 0 0  value hex 1 0 0 0

关闭：
sudo bpftool map update id 65(debug_map id)  key hex 0 0 0 0  value hex 0 0 0 0
```
