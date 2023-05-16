# 使用 eBPF 加速 Istio

## 使用场景

* 注入sidecar的p2p通信
* 没有注入 sidecar 的 p2p 通信

## 系统要求

* 最低：内核版本 >= 4.18 的分发
* 推荐：带有 Linux 5.4.0-74-generic 的 Ubuntu 20.04

## 依赖关系

* 不需要更改 linux 内核
* 不需要更改 Istio 和 Envoy (>= v1.10)
* 不需要更改 CNI 插件

同一主机上的 p2p 通信预计延迟减少 15%~20%。

## 本地调试

构建 Docker 镜像
```
docker build --network=host -t ${IMAGE_NAME} .
```

通过 Docker 加载 eBPF 镜像
```
docker run --mount type=bind,source=/sys/fs,target=/sys/fs,bind-propagation=rshared --privileged --name tcpip-bypass  ${IMAGE_NAME}
```

Daemonset 部署
```
kubectl apply -f deploy/bypass-tcpip-daemonset.yaml
```

构建 tcp-ip-pass 编译工具
```
docker build --platform=linux/amd64 -t docker.io/tanjunchen/tcp-ip-pass-tool:test -f Dockerfile.build_tool .  
docker push docker.io/tanjunchen/tcp-ip-pass-tool:test
```

构建 tcp-ip-pass 镜像
```
docker build --platform=linux/amd64  --network=host -t registry.baidubce.com/csm/ebpf-tanjunchen:test  -f Dockerfile.local  .
docker push registry.baidubce.com/csm/ebpf-tanjunchen:test
```

请求测试
```
kubectl  exec deployments/wrk -it -- curl -sI http://nginx:80
```

开启内核 debug 日志
```
开启：
sudo bpftool map update id x  key hex 0 0 0 0  value hex 1 0 0 0

关闭：
sudo bpftool map update id x  key hex 0 0 0 0  value hex 0 0 0 0
```

查看内核系统日志
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
