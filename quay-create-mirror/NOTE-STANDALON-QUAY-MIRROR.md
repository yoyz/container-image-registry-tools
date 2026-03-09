```markdown
# Using Mirror-Registry with Quay

If you use [mirror-registry](https://github.com/quay/mirror-registry), you need an additional pod running inside the `quay-app` pod.

## Podman Commands

```bash
[root@bastion421 ~]# podman pod ls
POD ID        NAME        STATUS      CREATED     INFRA ID      # OF CONTAINERS
f0b5344bce27  quay-pod    Running     5 days ago  24e46906fc10  4

[root@bastion421 ~]# podman ps
CONTAINER ID  IMAGE                                         COMMAND     CREATED     STATUS      PORTS                                       NAMES
24e46906fc10  registry.access.redhat.com/ubi8/pause:8.10-5  infinity    5 days ago  Up 5 days   0.0.0.0:8443->8443/tcp                      f0b5344bce27-infra
8e3abf3033d0  registry.redhat.io/rhel8/redis-6:1-190        run-redis   5 days ago  Up 5 days   0.0.0.0:8443->8443/tcp, 6379/tcp            quay-redis
8dfe2f954699  registry.redhat.io/quay/quay-rhel8:v3.12.3    repomirror  5 days ago  Up 5 days   0.0.0.0:8443->8443/tcp, 7443/tcp, 8080/tcp  quay-mirror
619697dcc7c1  registry.redhat.io/quay/quay-rhel8:v3.12.3    registry    5 days ago  Up 5 days   0.0.0.0:8443->8443/tcp, 7443/tcp, 8080/tcp  quay-app
```

## Service Unit Configuration

You can reuse the `quay-app.service` systemd unit and create a new one named `quay-mirror.service`.

### Modifications for `quay-mirror.service`

**Add/modify the following in the `[Unit]` section:**

```ini
Requires=quay-pod.service quay-redis.service quay-app.service
```

**In the `[Service]` section, update the `ExecStart` command:**

```ini
ExecStart=/usr/bin/podman run \
    --name quay-mirror \
    -v /opt//quay-config:/quay-registry/conf/stack:Z \
    -v sqlite-storage:/sqlite:Z \
    -v quay-storage:/datastorage:Z \
    --image-volume=ignore \
    --pod=quay-pod \
    --conmon-pidfile %t/%n-pid \
    --cidfile %t/%n-cid \
    --cgroups=no-conmon \
    --log-driver=journald \
    --replace \
    -e WORKER_COUNT_UNSUPPORTED_MINIMUM=4 \
    -e WORKER_COUNT=4 \
    registry.redhat.io/quay/quay-rhel8:v3.12.3 repomirror
```

### Notes
- Ensure the `quay-mirror.service` file is properly configured and enabled.
- The `quay-mirror` container will run as part of the `quay-pod` pod.
```
