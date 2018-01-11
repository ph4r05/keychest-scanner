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

## Dynamic inventory

```
cp keychest_inventory/keychest.py /etc/ansible/hosts.py
chmod +x /etc/ansible/hosts.py

ansible -m ping all -i /etc/ansible/hosts.py 
```

Resources:

- https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html
- https://adamj.eu/tech/2016/12/04/writing-a-custom-ansible-dynamic-inventory-script/
- https://github.com/BlueAcornInc/ansible-dbinventory