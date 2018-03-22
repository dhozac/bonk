# Bonk Ansible modules

## bonk_address
Manage bonk records with Ansible
### Usage example
```
- name: Update my A record
  connection: local
  bonk_record:
    state: present
    username: "{{ myuser }}"
    password: "{{ mypasswd }}"
    name: my-awesome.host.domain-name
    type: A
    zone: domain-name
    value: ip.ad.dr.ess
```
