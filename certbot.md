# Remote certbot domain validation

In order to perform domain validation for managed domains on the agent server the virtual host of the validated domain
has to be configured in a way it proxies `.well-known` directory to the local KeyChest agent running Certbot.

## Nginx

```
location / {
    proxy_pass       https://agent.keychest.net/_le/$host/.well-known/;
    proxy_set_header Host      $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

- May work only over http - debug.

## Apache

```
SSLProxyEngine On
SSLProxyCheckPeerCN on
SSLProxyCheckPeerExpire on

RewriteEngine on
RewriteCond %{HTTP_HOST} (.*)
RewriteRule "^/.well-known/(.*)$" "https://dev.keychest.net/_le/%{HTTP_HOST}/.well-known/$1" [P,L,QSA]
ProxyPassReverse ".well-known/"  "http://dev.keychest.net"
```

# Ansible

Installation

```
pip install git+https://github.com/ansible/ansible.git@devel#egg=ansible
```

https://docs.ansible.com/ansible/latest/intro_inventory.html
https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-ansible-on-centos-7

## Hosts

/etc/ansible/hosts

```
[webservers]
34.248.161.88 ansible_connection=ssh  ansible_user=ec2-user  ansible_ssh_private_key_file=/etc/ansible/key01.pem
```

## Basic config

```
ansible -m ping all
ansible -m shell -a 'free -m' all
```

### Ansible web server install

```
# redhat based
ansible -m yum -a 'pkg=nginx state=installed update_cache=true' -s all

# ubuntu based
ansible -m apt -a 'pkg=nginx state=installed update_cache=true' -s all
```

