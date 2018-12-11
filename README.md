
# SSH server and client supporting OAuth2 resource access and OpenID Connect authentication

This readme is intended o be simpler and more specific version of 
[Original Dropbear README](README)
if you want to use Dropbear with **OAuth2 authentication**.
It also adds instructions for OAuth2 specific programs like `oauth2agent` and `userinfo`

programs:
 - `dropbear` ssh server
 - `dbclient` ssh client
 - `oauth2agent` listening on unix socket and handling incoming OAuth2 requests e.g. from `dbclient` or `userinfo`.
    Note that it can be forwarded same way as SSH agent.
 - `userinfo` Simple example program using oauth2agent



## Server instalation
[Tested on Ubuntu 18/16/14, Debian 9, CentOS 7]

Will install `dropbear` and `dropbearkey` binaries from sources to `/usr/sbin/` resp. `/usr/bin/`.
It will generate host key to be used by `dropbear` server. And swap `dropbear` instead of `sshd`.
Then Dropbear server will be ready to accept incoming connections and authenticate via OAuth2.

IMPORTANT: Make sure you have **backdoor access** beside ssh 
since in some point you have to kill `sshd` and run `dropbear` instead.
e.g. `sshd` running on *different port*, *VNC* or *desktop UI*.  
NOTE: Tested under `root`. So you have to use `sudo` somewhere.

#### Instalation steps

1.  **Install dependencies**
	```
	sudo apt-get install build-essential git vim autoconf zlib1g-dev libcurl4-openssl-dev
	```
	*CentOS:*
	```
	sudo yum install make gcc git vim autoconf zlib-devel libcurl-devel
	```
2.  **Download sources** to `/tmp/`
	```
	cd /tmp/ && \
	git clone https://github.com/ondrejvelisek/dropbear.git && \
	cd /tmp/dropbear/ && \
	git checkout oauth2-auth-support
	```
3.  **Configure build**
	```
	autoconf && \
	autoheader && \
	./configure && \
	cp default_options.h localoptions.h
	```
	Edit build options to support OAuth2 authentication 
	(feel free to read and change other options)
	```
	vim localoptions.h
	```
	[A] **OpenID Connect authentication** configuration
	Example: Google identity provider
	```
	#define DROPBEAR_SVR_OIDC_AUTH 1
	#define DROPBEAR_SVR_PUBKEY_AUTH 1 // Can be turned off, if you want
	
	#define DROPBEAR_SVR_OIDC_ISSUER "https://accounts.google.com"
	#define DROPBEAR_SVR_OIDC_AUTHORIZATION_ENDPOINT "https://accounts.google.com/o/oauth2/v2/auth"
	#define DROPBEAR_SVR_OIDC_TOKEN_ENDPOINT "https://oauth2.googleapis.com/token"
	#define DROPBEAR_SVR_OIDC_TOKEN_INTROSPECTION_ENDPOINT "https://www.googleapis.com/oauth2/v3/tokeninfo"
	#define DROPBEAR_SVR_OIDC_SCOPES_REQUIRED "https://www.googleapis.com/auth/plus.me"
	#define DROPBEAR_SVR_OIDC_CODE_CHALLENGE_METHODS_SUPPORTED "plain S256"
	#define DROPBEAR_SVR_OIDC_CLIENT_ID "<client_id>"
	#define DROPBEAR_SVR_OIDC_CLIENT_SECRET "<client_secret>" // Not real secret in case of native app
	#define DROPBEAR_SVR_OIDC_REDIRECT_URI_PORT 22080
	#define DROPBEAR_SVR_OIDC_REDIRECT_URI_PATH "/oauth2_callback"
	```
	[B] **OAuth2 resource access** configuration
	Example: MitreID Connect
	```
	#define DROPBEAR_SVR_OAUTH2_AUTH 1
	#define DROPBEAR_SVR_PUBKEY_AUTH 1 // Can be turned off, if you want

	#define DROPBEAR_SVR_OAUTH2_INTROSPECTION_ENDPOINT "https://mitreid.org/introspect"
	#define DROPBEAR_SVR_OAUTH2_RESOURCE_SERVER_ID "<resource_server_id>" 
	#define DROPBEAR_SVR_OAUTH2_RESOURCE_SERVER_SECRET "<resource_server_secret>"
	#define DROPBEAR_SVR_OAUTH2_SCOPES_REQUIRED "<required_scope>" // List of space delimited scopes required to access the server
	```
4.  **Build and install** server and key generator
	```
	sudo CFLAGS=-std=gnu99 make dropbear dropbearkey && \
	sudo cp dropbear /usr/sbin/ && \
	sudo cp dropbearkey /usr/bin/ && \
	cd ~
	```
5.  **Generate host key**  
	NOTE: You can convert current `sshd` keys instead (see `dropbearkey` manual)
	```
	cd ~ && \
	sudo mkdir /etc/dropbear && \
	sudo dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
	```
6.  **Authorization mapping** configuration  
	To authorize someone you must configure authorization mapping between OAuth2 accounts and local account.
	To do so simply create file `/home/<local_account>/.oauth2-ssh/oauth2-mappings` with one line formatted like below:
	```
	oauth2_account_id_1:oauth2_account_id_2:oauth2_account_id_3
	```
	or file `/etc/oauth2-ssh/oauth2-mappings` with following mapping format
	```
	local_account_1:oauth2_account_id_1:oauth2_account_id_2:oauth2_account_id_3
	local_account_2:oauth2_account_id_1
	local_account_3:oauth2_account_id_2:oauth2_account_id_4
	```
	NOTE: OAuth2 account is authorized if it is placed in at least one of those files.
7.  **Swap servers** `sshd` for `dropbear` server  
	CRITICAL: If your only access to machine is through `ssh` and you do this command via such connection
	if this command fails you can **lose access to the whole machine**. Because of it we strongly recommend 
	run following lines through different channel. e.g. ssh on *different port*, *VNC* or *desktop UI*. 
	```
	sudo service ssh stop && \
	sudo dropbear || \
	sudo service ssh start
	```
	*CentOS:*
	```
	sudo service sshd stop && \
	sudo dropbear || \
	sudo service sshd start
	```
	(If you didn't follow our recommendation and swap ssh servers via ssh connection you could be disconnected. 
	In such case connect to the machine again)

#### Next possible steps
1.  **Check connection**
	Since host key has been changed you need to remove it from known hosts
	```
	sudo ssh-keygen -R <hostname>
	dbclient <username>@<hostname>
	```
2.  **Check dropbear** server has replaced `sshd`
	```
	sudo netstat -tulpn | grep :22
	```
	You should see `dropbear` at the end of line
3.  **Install Dropbear client** (see section *Client installation*)
4.  **Clean sources**
	```
	rm -rf /tmp/dropbear/
	```
5.  **Integrate dropbear** to system init scripts to survive machine reboot  
	[**TBD**]




## Client instalation
[Tested on Ubuntu 18/16/14, Debian 9, macOS 10.14]

Will install `dbclient` binary from sources to `/usr/bin/`.
Then Dropbear client will be ready to connect to Dropbear server and authenticate via OAuth2.

NOTE: Tested under `root`. So somewhere you will have to use `sudo`

#### Instalation steps

1.  **Install dependencies**
	```
	sudo apt-get install build-essential git vim autoconf zlib1g-dev libcurl4-openssl-dev
	```
	*CentOS:*
	```
	sudo yum install make gcc git vim autoconf zlib-devel libcurl-devel
	```
	*macOS:* Install `xcode` and `cctools`
2.  **Download sources** to `/tmp/`
	```
	cd /tmp/ && \
	git clone https://github.com/ondrejvelisek/dropbear.git && \
	cd /tmp/dropbear/ && \
	git checkout oauth2-auth-support
	```
3.  **Configure build**
	```
	autoconf && \
	autoheader && \
	./configure && \
	cp default_options.h localoptions.h
	```
	Edit build options to support OAuth2 authentication 
	(feel free to read and change other options)
	```
	vim localoptions.h
	```
	Example: Google identity provider
	```
	#define DROPBEAR_CLI_PUBKEY_AUTH 0 
	#define DROPBEAR_CLI_OAUTH2_AUTH 1 
	```
	[A] **OpenID Connect authentication** configuration
	Example: Google identity provider
	```
	#define DROPBEAR_CLI_OIDC_AUTH 1 
	#define DROPBEAR_CLI_PUBKEY_AUTH 0 
	```
	[B] **OAuth2 resource access** configuration
	Example: MitreID Connect
	```
	#define DROPBEAR_CLI_OAUTH2_AUTH 1
	#define DROPBEAR_CLI_PUBKEY_AUTH 0 

	#define DROPBEAR_CLI_OAUTH2_ISSUER "https://mitreid.org/"
	#define DROPBEAR_CLI_OAUTH2_AUTHORIZATION_ENDPOINT "https://mitreid.org/authorize"
	#define DROPBEAR_CLI_OAUTH2_TOKEN_ENDPOINT "https://mitreid.org/token"
	#define DROPBEAR_CLI_OAUTH2_USERINFO_ENDPOINT "https://mitreid.org/userinfo"
	#define DROPBEAR_CLI_OAUTH2_SUPPORTED_CODE_CHALLENGE_METHODS "plain S256" // Space delimited
	#define DROPBEAR_CLI_OAUTH2_CLIENT_ID "<client_id>"
	#define DROPBEAR_CLI_OAUTH2_CLIENT_SECRET "<client_secret>" // Not real secret for native public app, pass empty string if not needed
	#define DROPBEAR_CLI_OAUTH2_REDIRECT_URI_PORT 22080
	#define DROPBEAR_CLI_OAUTH2_REDIRECT_URI_PATH "/oauth2_callback"
	#define DROPBEAR_CLI_OAUTH2_SCOPES_REQUIRED "<required_scope>" // Space delimited
	```
4.  **Build and install** client
	```
	sudo CFLAGS=-std=gnu99 make dbclient && \
	sudo cp dbclient /usr/bin/ && \
	cd ~
	```

#### Next possible steps
1.  **Check functionality**  
	NOTE: If you disabled public key authentication you need to connect to configured Dropbear server 
	since its currently only one who supports OAuth2 authentication.
    ```
    dbclient <username>@<hostname>
    ```
    Your browser will open. Follow instructions, authenticate at Identity provider you configured
    and you will be connected to server. 
2.  **Clean sources**
    ```
    rm -rf /tmp/dropbear/
    ```
    
    
## OAuth2 Agent instalation
[Tested on Ubuntu 18/16/14, Debian 9, CentOS 7, macOS 10.14]

Will install `oauth2agent` to `/usr/sbin/` and run it.
Then Agent will be ready to accept incoming connections and authenticate via OAuth2.

It has two options. `-d` to run it in background (daemon), `-v` to run debug mode (verbose).
In either way it kills its siblings and prints an environment variable which needs to be provided
to SSH client.

NOTE: Tested under `root`. So somewhere you will have to use `sudo`

#### Instalation steps

1.  **Install dependencies**
	```
	sudo apt-get install build-essential git vim autoconf libcurl4-openssl-dev
	```
	*CentOS:*
	```
	sudo yum install make gcc git vim autoconf libcurl-devel
	```
	*macOS:* Install `xcode` and `cctools`
2.  **Download sources** to `/tmp/`
	```
	cd /tmp/ && \
	git clone https://github.com/ondrejvelisek/dropbear.git && \
	cd /tmp/dropbear/ && \
	git checkout oauth2-auth-support
	```
3.  **Build and install** agent
	```
	autoconf && \
	autoheader && \
	./configure --disable-zlib --without-zlib
	sudo CFLAGS=-std=gnu99 make oauth2agent && \
	sudo cp oauth2agent /usr/sbin/ && \
	cd ~
	```
4.  **Run** agent
	```
	oauth2agent
	```

#### Next possible steps
1.  **Check daemon** is running 
	```
	ps -aux | grep oauth2agent
	```
	You should see `oauth2agent` at the end of line
2.  **Check functionality**  
	See installation steps for `userinfo` example program
	```
	userinfo
	```
	It should authenticate you and print your name
	See `/tmp/oauth2agent.log`
3.  **Integrate oauth2agent** to system to survive machine reboot  
	[**TBD**]
    
    
## Userinfo example program instalation
[Tested on Ubuntu 18/16/14, Debian 9, CentOS 7, macOS 10.14]

Will install `userinfo` to `/usr/bin/`.
Then Userinfo program will be ready to connect to OAuth2 Agent and authenticate via OAuth2.

NOTE: Tested under `root`. So somewhere you will have to use `sudo`

#### Instalation steps

1.  **Install dependencies**
	```
	sudo apt-get install build-essential git vim autoconf libcurl4-openssl-dev
	```
	*CentOS:*
	```
	sudo yum install make gcc git vim autoconf libcurl-devel
	```
	*macOS:* Install `xcode` and `cctools`
2.  **Download sources** to `/tmp/`
	```
	cd /tmp/ && \
	git clone https://github.com/ondrejvelisek/dropbear.git && \
	cd /tmp/dropbear/ && \
	git checkout oauth2-auth-support
	```
3.  **Build and install**
	```
	autoconf && \
	autoheader && \
	./configure --disable-zlib --without-zlib
	sudo CFLAGS=-std=gnu99 make userinfo && \
	sudo cp userinfo /usr/bin/ && \
	cd ~
	```

#### Next possible steps
1.  **Check functionality**
	```
	userinfo
	```
	It should authenticate you and print your name