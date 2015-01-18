# ctfmemusage
Compute and display the memory usage of the CTF data set, the `libbsdctf` and
comparisong to the DWARF data set.

## Build
```
$ ninja
```
### Dependencies
 * libbsdctf
 * libelf

## Usage
 * `-h` print help message
 * `-l` insepct the library storage/memory efficiency 
 * `-d` inspect the CTF/DWARF comparison
 * `-r` print ratio
 * `-s` when used in combination with `-r` will print only the ratio number 

## Run
Inspect general library implementation and DWARF comparison:
```
$ ctfmemusage -dlr /boot/kernel/kernel
CTF memory vs. CTF storage
--------------------------
   Memory usage: 6485904 bytes
  Storage usage: 3144954 bytes
          Ratio: 2.062

DWARF storage vs. CTF storage
-----------------------------
  DWARF: 34168436 bytes
    CTF: 3144954 bytes
  Ratio: 10.865
```

Compute average storage inflation by the library (results may vary depending on
your system):
```
$ find /boot/kernel -name '*.symbols' -exec ctfmemusage -lrs {} \; | awk
‘{+=$1}END{print s/NR}'
2.67788
```

## Author
Daniel Lovasko (lovasko@freebsd.org)

