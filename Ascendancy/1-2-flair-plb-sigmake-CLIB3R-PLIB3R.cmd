@CALL 0-flair-path.cmd

plb.exe    "d:\IDA Projects\Ascendancy\LIB386\v10.0a\DOS\CLIB3R.LIB" W100A32LIB.PAT
plb.exe -a "d:\IDA Projects\Ascendancy\LIB386\v10.0a\PLIB3R.LIB"     W100A32LIB.PAT
sigmake.exe -n"Watcom 10.0a 32bit Library" W100A32LIB.PAT W100A32LIB.SIG
