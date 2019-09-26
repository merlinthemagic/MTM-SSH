### What is this?

Make SSH connections to other hosts and issue commands to the shell.
You can also connect to one device and use that to connect to another.
e.g. ssh to a linux server, use that shell to connect to a routerOS device.
Then use the second device to connect to a third device (linux or routeros) and so on

You can execute any command you want. There is full parity with the underlying shells

#### Get a remote shell on a linux server using password
```
$ctrlObj	= \MTM\SSH\Factories::getShells()->passwordAuthentication("IpAddress", "username", "password");
```

#### Get a remote shell on a device running mikrotik routeros using password
```
$username	= \MTM\SSH\Factories::getShells()->getRouterOsTool()->getFormattedUsername("username");
$ctrlObj	= \MTM\SSH\Factories::getShells()->passwordAuthentication("IpAddress", $username, "password");
```

#### Get a remote shell on a linux server using public key authentication
```
$key		= "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgk.....
....S8dBQ==
-----END PRIVATE KEY-----";

$ctrlObj	= \MTM\SSH\Factories::getShells()->keyAuthentication("IpAddress", "username", $key);
```
#### Get a remote shell on a device running mikrotik routeros using public key authentication
```
$key		= "-----BEGIN PRIVATE KEY-----
MIIEvAIBBDANBgk.....
....S8dBQ==
-----END PRIVATE KEY-----";
$username	= \MTM\SSH\Factories::getShells()->getRouterOsTool()->getFormattedUsername("username");
$ctrlObj	= \MTM\SSH\Factories::getShells()->keyAuthentication("IpAddress", $username, $key);
```

#### Get a remote shell on a linux server using an existing shell
```
//no public key auth yet
$ctrlObj2	= \MTM\SSH\Factories::getShells()->passwordAuthentication("IpAddress", "username", "password", $ctrlObj);
//NOTE: Both existing shell ($ctrlObj) and built on shell ($ctrlObj2) will execute on the second host
```
#### Get a remote shell on a device running mikrotik routeros using an existing shell
```
//no public key auth yet
$username	= \MTM\SSH\Factories::getShells()->getRouterOsTool()->getFormattedUsername("username");
$ctrlObj2	= \MTM\SSH\Factories::getShells()->passwordAuthentication("IpAddress", $username, "password", $ctrlObj);
//NOTE: Both existing shell ($ctrlObj) and built on shell ($ctrlObj2) will execute on the second host
```


#### Start running commands: linux
```
$data		= $ctrlObj->getCmd("whoami")->exec()->get();
echo $data; //the name of the user you connected with

$ctrlObj->getCmd("cd /var")->exec()->get();
$data		= $ctrlObj->getCmd("ls -sho --color=none")->exec()->get();
echo $data; //directory and file listing from /var
```

#### Start running commands: routeros
```
$data		= $ctrlObj->getCmd("/system resource print")->exec()->get();
echo $data; //list of system resources

$data		= $ctrlObj->getCmd("/interface print")->exec()->get();
echo $data; //list of interfaces
```