
# SSH server and client supporting OAuth2 authentication
(OpenID Connect core included)

This readme is intended o be simpler and more specific version of 
[Original Dropbear README](README)
if you want to use Dropbear with **OAuth2 authentication**.

## Server instalation
[Tested on Ubuntu 18/16/14, Debian 9, CentOS 7]

Will install `dropbear` and `dropbearkey` binaries from sources to `/usr/sbin/` resp. `/usr/bin/`.
It will generate host key to be used by `dropbear` server. And swap `dropbear` instead of `sshd`.
Then Dropbear server will be ready to accept incoming connections and authenticate via OAuth2.

IMPORTANT: Make sure you have **backdoor access** beside ssh 
since in some point you have to kill `sshd` and run `dropbear` instead.
e.g. `sshd` running on *different port*, *VNC* or *desktop UI*.  
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
2.  **Download sources** to `/tmp/`
	```
	cd /tmp/ && \
	git clone https://github.com/ondrejvelisek/dropbear.git && \
	cd /tmp/dropbear/ && \
	git checkout oauth2-auth-support
	```
3.  **Configure build** to support OAuth2 authentication
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
	#define DROPBEAR_SVR_PUBKEY_AUTH 1 // Can be turned off, if you want
	#define DROPBEAR_SVR_OAUTH2_AUTH 1
	
	#define DROPBEAR_SVR_OAUTH2_ISSUER "https://accounts.google.com"
	#define DROPBEAR_SVR_OAUTH2_AUTHORIZATION_ENDPOINT "https://accounts.google.com/o/oauth2/v2/auth"
	#define DROPBEAR_SVR_OAUTH2_TOKEN_ENDPOINT "https://oauth2.googleapis.com/token"
	#define DROPBEAR_SVR_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT "https://www.googleapis.com/oauth2/v3/tokeninfo"
	#define DROPBEAR_SVR_OAUTH2_SCOPES_REQUIRED "https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
	#define DROPBEAR_SVR_OAUTH2_CODE_CHALLENGE_METHODS_SUPPORTED "plain S256"
	#define DROPBEAR_SVR_OAUTH2_CLIENT_ID "<client_id>"
	#define DROPBEAR_SVR_OAUTH2_CLIENT_SECRET "<client_secret>" // Not real secret in case of native app
	#define DROPBEAR_SVR_OAUTH2_REDIRECT_URI_PORT 22080
	#define DROPBEAR_SVR_OAUTH2_REDIRECT_URI_PATH "/oauth2_callback"
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
6.  **Swap servers** `sshd` for `dropbear` server  
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
	ssh <username>@<hostname>
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
[Tested on Ubuntu 18/16/14, Debian 9]

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
2.  **Download sources** to `/tmp/`
	```
	cd /tmp/ && \
	git clone https://github.com/ondrejvelisek/dropbear.git && \
	cd /tmp/dropbear/ && \
	git checkout oauth2-auth-support
	```
3.  **Configure build** to support OAuth2 authentication
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