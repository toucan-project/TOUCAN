# TOUCAN
Toucan is a canary framework that can be used to work with office documents and PDFs. 
<!-- vim-markdown-toc GitLab -->

* [Prerequisites](#prerequisites)
* [Preparation](#preparation)
    * [Creating local inventory](#creating-local-inventory)
        * [Hosts file](#hosts-file)
        * [Main server inventory](#main-server-inventory)
        * [Node server inventory](#node-server-inventory)
        * [Generate a CA certificate](#generate-a-ca-certificate)
* [Installation](#installation)

<!-- vim-markdown-toc -->

## Prerequisites
There are two machines required for this to work.

1. Canary machine, with an HTTP server and SMB.
2. Alert machine, has DNS and `syslog-ng` listeners.
3. A subdomain, having the alert machine as the [authoritative DNS server cracked](https://www.dnsknowledge.com/whatis/authoritative-name-server/).

The canary machine pushes logs to the alert machine, and in case of an event coming from a canary document, sends an alert to a predefined user.

It is recommended to use Ubuntu 19.xx as server OS. 

## Preparation
Create a user account on both machines for deploying the tool. If you have no inspiration, use `deploy`. Setup the `.ssh` folder with a public key for the user. The user must be added to the `sudo` group.

```bash
$ sudo useradd deploy -G sudo -s /bin/bash
```

Additionally, configure the `deploy` user to have a strong password.

```bash
$ sudo passwd deploy
```

Then login as the user, add a public key to the `.ssh/authorized_keys` file, and set the correct permissions:

```bash
deploy@server:~$ mkdir .ssh && cd .ssh
deploy@server:/home/deploy/.ssh$ cat > authorized_keys <<EOF
PASTE YOU PUBLIC KEY HERE
EOF
deploy@server:~$ chmod -R 0700 .ssh
```

After verifying that the connection works with the public key, and repeat the same process for the other server.

Now install Ansible on your local machine. This can be done with `python3-pip`:

```bash
$ pip3 install ansible
```

### Creating local inventory
To initialize the servers you must create a local inventory for Ansible to get the variables from. The configuration files are stored in the [inventory](https://github.com/toucan-project/TOUCAN/inventory) directory.

#### Hosts file
This file defines the targets for the Ansible deployment. The alias for the host, and the IP address.

`inventory/hosts:`
```yaml
[canary_main]
203.0.113.24

[canary_nodes]
203.0.113.25
```

The actual variables are stored in the separate `group_vars` directory. They will be defined in the next step.

#### Main server inventory
An example inventory file for the main canary (syslog) server:

`inventory/canary_main/vars.yml:`
```yaml
label: master
syslog_ip: 203.0.113.24             # ip of the machine itself
nginx_ip: 203.0.113.25              # the node machine, with services
hostname: toucan.example.org
main_domain: example.org
auth_domain: subdomain.example.org
ansible_ssh_user: deploy            # the user to SSH with
ansible_become_user: root
ansible_python_interpreter: /usr/bin/python3
mysql_user: tadmin
```

As you may have noticed, there are no secrets stored in this file, they are supposed to be stored in the `vault.yml` file. Additionally, when using `pass`, there is Ansible integration, so you can actually use this password manager. More information can be found [here](https://docs.ansible.com/ansible/latest/plugins/lookup/passwordstore.html)

`inventory/canary_main/vault.yml:`
```yaml
secret_key: <key>                       # django secret key (use ./manage.py generatesecret here)
redis_password: <secret_password>       # long redis password
mysql_password: <secret_password>
ansible_sudo_pass: <secret_password>    # password of deploy user
vault_key: <key>                        # vault key for remote inventory on main server (syslog)
```

When done with configuring the `vault.yml`, use `ansible-vault` to encrypt the file:

```bash
$ ansible-vault encrypt vault.yml
```
Use a long and secure password and save it in, preferably, a password manager.

#### Node server inventory
The node server is where the incoming canaries will be received. It has an SMB and HTTP server exposed, and the logs are sent over to the main canary server.

An example configuration file looks as follows:

`inventory/group_vars/canary_node/vars.yml:`
```yaml
label: node                     # the ip of the syslog server
syslog_ip: 203.0.113.24         # the hostname of the syslog server
syslog_host: toucan.example.org # ip of this machine
hostname: 203.0.133.25
ansible_ssh_user: deploy
ansible_become_user: root
ansible_python_interpreter: /usr/bin/python3
```

Also for the node a `vault.yml` is specified:

`inventory/group_vars/canary_node/vault.yml:`
```yaml
ansible_sudo_pass: <secret_password>
```

Specify the sudo password for the `deploy` user, and run the `ansible-vault encrypt` command again, to encrypt the vault.

#### Generate a CA certificate
The syslog server is setup with mTLS. Clients need to be authenticated with a client certificate. To generate the certificates go into the `CA/managed_certificates` and run `./generate_ca.sh`. If you do not feel like repeating yourself, fill out some details in `openssl.cnf` under `req_distinguished_name`.

When done generating the certificate, and before making a deployment, generate two client certificates. Go back into `CA` and run `./add_new_client.sh`.
For the first certificate, fill out the fully qualified hostname of the main (syslog) server. As defined by the `syslog_host` Ansible value. In the case of our (mock) configuration, this would be: `toucan.example.org`.

The second client certificate can be generated with either the hostname of the canary node server, or the IP address. Remember the 'node hash', as you need to define the hash when running the deployment, so that Ansible knows which certificate to pick up.

## Installation
Initialize the submodule containing the Ansible deploy scripts.

```bash
$ git submodule update --init
```

This will add the deployment scripts to the Ansible directory. Go into the `ansible` directory and run the following command:

```bash
$ ansible-playbook deploy-syslog.yml --ask-vault-pass -i ../inventory
```

When asked for the node hash, fill out the hash identifier for the main syslog server, the deployment script will whitelist your current IP address to access the admin interface when the deployment is complete. 

When the installation is done, and you are greeted by the following login portal: <screenshot>


The deployment was successful. Now deploy the canary node server, using:

```bash
$ ansible-playbook deploy-node.yml --ask-vault-pass -i ../inventory
```

Fill in the corresponding node hash, and wait for the deployment to complete.
