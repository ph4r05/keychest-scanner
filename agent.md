# Agents

Multiple agent setup.

One master can have more slave agents, typically located in the isolated network segments so agents can perform scanning
of the internal infrastructure (out of reach for master scanner) and report results to the master.

On the master one user per agent is created. All are grouped in `agents` group.

```bash
sudo groupadd agents
```

## Master config - add an agent

```bash
AGENT_UNAME="agent-test"
```


```bash
sudo useradd -G agents -m ${AGENT_UNAME}
su ${AGENT_UNAME}
ssh-keygen
```

Add agent's public SSH key to the authorized keys file, no action possible, just local forward:

/home/${AGENT_UNAME}/.ssh/authorized_keys:

```
no-agent-forwarding,no-X11-forwarding,command="read a; exit" ssh-rsa ...
```

Better / more strict:

```
command="echo 'Port forwarding only account.'",no-X11-forwarding,no-agent-forwarding,no-pty,permitopen="localhost:33080",permitopen="127.0.0.1:33080 ssh-rsa ..."
```

```
chmod 0644 /home/${AGENT_UNAME}/.ssh/authorized_keys
```

## Agent setup

Configuring agent server

 - Edit main configuration file:
   - Enable agent mode
   - Set endpoint to `http://127.0.0.1:33080`
   - Set api key - generated on the master

 - Configure SSH tunnel to access scanner API port.

```bash
ssh-keygen
sudo yum install --enablerepo=epel autossh
```

SSH tunnel to the master, keep connection online with supervisor:

`/etc/supervisord.d/ssh-tunel.conf`

```ini
[program:ssh-tunel]
directory=/home/ec2-user
command=autossh -M 0 -n -N -L 33080:localhost:33080 agent-test@dev.keychest.net
user=ec2-user
autostart=true
autorestart=true
stderr_logfile=/var/log/sshtun.err.log
stdout_logfile=/var/log/sshtun.out.log
```


