# What is it?

If you have a webserver running on one computer (say your development laptop),
and you want to expose it securely (ie HTTPS) via a public URL, SirTunnel
allows you to easily do that.

# How do you use it?

If you have:

* A SirTunnel [server instance](#running-the-server) running on `example.com`.
* A copy of the sirtunnel.py script available on the PATH or any directory of the server.
* An SSH server running on port 22 of `example.com`.
* A webserver running on port 8080 of your laptop.

And you run the following command on your laptop:

```bash
ssh -tR 9001:localhost:8080 example.com sirtunnel.py --fqdn subdomain.example.com --port 9001 --authentication username:password
```

Now any requests to `https://subdomain.example.com` will be proxied to your local
webserver.  
HTTP Basic authentication will be used to authenticate the requests with `username` and the password `password`.  
the `--authentication` switch is optional.  


# How does it work?

The command above does 2 things:

1. It starts a standard [remote SSH tunnel][2] from the server port 9001 to
   local port 8080.
2. It runs the command `sirtunnel.py --fqdn subdomain.example.com --port 9001` on the server.  
   The python script uses the Caddy API to create a reverse proxy vhost `subdomain.example.com`  
   which uses the upstream port 9001.  
   Caddy automatically retrieves an HTTPS cert for `subdomain.example.com`.  

**Note:** The `-t` is necessary so that doing CTRL-C on your laptop stops the  
`sirtunnel.py` command on the server, which allows it to clean up the tunnel  
on Caddy. Otherwise it would leave `sirtunnel.py` running and just kill your  
SSH tunnel locally.  


# How is it different?

There are a lot of solutions to this problem. In fact, I've made something of  
a hobby of maintaining [a list][0] of the ones I've found so far.  

The main advantages of SirTunnel are:  
  
* Minimal. It leverages [Caddy][1] and whatever SSH server you already have  
  running on your server. Other than that, it consists of a short Python  
  script on the server.  That's it. Any time you spend learning to customize  
  and configure it will be time well spent because you're learning Caddy and  
  your SSH server.  
* 0-configuration. There is no configuration on the server side.  Just two CLI  
  arguments (of wich only one is required).  
* Essentially stateless. The only state is the certs (which is handled entirely  
  by Caddy) and the tunnel mappings, which are ephemeral and controlled by the  
  clients.  
* Automatic HTTPS certificate management. Some other solutions do this as well,  
  so it's important but not unique.  
* No special client is required. You can use any standard SSH client that  
  supports remote tunnels. Again, this is not a unique feature.  


# Running the server

Assuming you already have an ssh server running, getting the SirTunnel server  
going consists of simply running the provided docker-compose deployment.    
The `install.sh` and `run_server.sh` scripts have been adjusted accordingly.  


# Future Features

SirTunnel is intended to be a minimal tool. As such, I'm unlikely to add many  
features moving forward. However, the simplicity makes it easier to modify  
for your needs. For example, see this fork which adds functionality to help  
multiple users avoid overwriting each others' tunnels:  

https://github.com/matiboy/SirTunnel  


[0]: https://github.com/anderspitman/awesome-tunneling

[1]: https://caddyserver.com/

[2]: https://www.ssh.com/ssh/tunneling/example#remote-forwarding
