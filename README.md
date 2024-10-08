# apisix-instance-agent

apisix instance agent (abbr. aia) ,is a cli for manage apisix instance, eg. read and write config.yaml, reload apisix, stop apisix.

```bash
./aia --help
Usage of ./aia:
      --allowed-ip string           Comma-separated list of allowed IPs
      --apisix-config string        apisix-config
      --apisix-reload-cmd string    apisix-reload-cmd
      --apisix-restart-cmd string   apisix-restart-cmd
      --apisix-start-cmd string     apisix-start-cmd
      --apisix-stop-cmd string      apisix-stop-cmd
  -h, --help                        aia, apisix instance agent.
      --listen string               listen address (default ":5980")
      --release-mode string         gin.ReleaseMode (default "true")
      --version                     print version
      --x-api-key string            x-api-key (default "your-secret-api-key")
```

## usage
```bash

openssl rand -base64 32
1kD+yHW1hjE7Dy0RzVjIChENoR0TaI9Zt30K5rzDzeQ=


./aia \
--listen :5980 \
--apisix-config /opt/apisix/conf/config.yaml \
--apisix-reload-cmd "docker exec -t apisix bash -c \"apisix reload\"" \
--apisix-stop-cmd "docker stop apisix || true" \
--apisix-start-cmd "docker start apisix" \
--apisix-restart-cmd "docker restart apisix" \
--x-api-key "1kD+yHW1hjE7Dy0RzVjIChENoR0TaI9Zt30K5rzDzeQ=" \
--allowed-ip 192.168.1.0/24,127.0.0.1,172.17.0.0/16
```

## http rest api

### read/write config

```bash
## read
curl --fail -sS -H "X-API-KEy: 1kD+yHW1hjE7Dy0RzVjIChENoR0TaI9Zt30K5rzDzeQ=" -X GET http://127.0.0.1:5980/api/v1/config | jq -r ".data" | base64 -d
```

```bash
## write
curl --fail -sS -H "X-API-KEy: 1kD+yHW1hjE7Dy0RzVjIChENoR0TaI9Zt30K5rzDzeQ=" -X POST http://127.0.0.1:5980/api/v1/config -d "{\"data\": \"$base64Str\"}"
```

### apisix instance operate

```bash
## reload config
curl --fail -sS -H "X-API-KEy: 1kD+yHW1hjE7Dy0RzVjIChENoR0TaI9Zt30K5rzDzeQ=" -X GET http://127.0.0.1:5980/api/v1/reload | jq
## stop
curl --fail -sS -H "X-API-KEy: 1kD+yHW1hjE7Dy0RzVjIChENoR0TaI9Zt30K5rzDzeQ=" -X GET http://127.0.0.1:5980/api/v1/stop | jq
## start
curl --fail -sS -H "X-API-KEy: 1kD+yHW1hjE7Dy0RzVjIChENoR0TaI9Zt30K5rzDzeQ=" -X GET http://127.0.0.1:5980/api/v1/start | jq
## restart
curl --fail -sS -H "X-API-KEy: 1kD+yHW1hjE7Dy0RzVjIChENoR0TaI9Zt30K5rzDzeQ=" -X GET http://127.0.0.1:5980/api/v1/restart | jq
```

