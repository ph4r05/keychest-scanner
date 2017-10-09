# Agents

```bash
sudo groupadd agents
```

## Per agent setup - master side

```bash
sudo useradd -G agents -m agent-test
su agent-test
ssh-keygen
```

/home/agent-test/.ssh/authorized_keys:

```
no-agent-forwarding,no-X11-forwarding,command="read a; exit" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCuDc97sA8lq9d0uCfLVQt3cNvSk3hOC6i8lsk5JrWvKC02aJTbIZrm2NDZn9/9gsf5g04lRFxiQLwII+IiP+6xe4R0nJRZfgmmlOyAKBDc/H3cBmJqJnFxuectzEoCiUeA+pOIza/gmjjqkmdNFimZump20A3sYgbzhZ+Q6F4Qo6oZF3ntUflSckIsVr2dBhF/ZQM3LhfO/56T01EdoY4dEBULbsHYGKjm8Wl+wLKAL3Km5w0tMShKn6WJjwhGaZ5qpAcNiAnXgGw0nMPpZsMVyG6KpPbDq7t+IhSDQEmMtuKVQnSsvOGJHt9JOpW2pO2/BgVyBXsdEZxRRiVa51cZ root@vps2
```

```
chmod 0644 /home/agent-test/.ssh/authorized_keys
```

## Agent setup

```bash
ssh-keygen
```

SSH tunnel, keep online with supervisor:

`/etc/supervisord.d/ssh-tunel.conf`

```ini
[program:ssh-tunel]
directory=/home/ec2-user
command=ssh agent-test@keychest.net -L 33080:localhost:33080
user=ec2-user
autostart=true
autorestart=true
stderr_logfile=/var/log/sshtun.err.log
stdout_logfile=/var/log/sshtun.out.log
```


