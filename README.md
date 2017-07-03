# rlmlog
The main porpouse of this program is:

Parses the RLM ReportLog file (*.rl) into a CSV format.

Search records for checkin, checkout e deny (OUT, IN or DENY) separately because each 

record has your own output format

There's no option now, to output ALL records together.

    usage: rlmlog.py [-h] [-y YEAR | -d SDATE] [-u SUSER] [-t REG_TYPE] [-v]
                     [filename]

    positional arguments:
      filename           The input log file to be parsed. REQUIRED

    optional arguments:
      -h, --help         show this help message and exit
      -y YEAR            Year (YYYY) you want to search.
      -d SDATE           Date (MMDDYYYY) you want to search.
      -u SUSER           User you want to search.
      -t REG_TYPE        Type of record you want: [IN, OUT or DENY]. REQUIRED
      -v, -V, --version  show program's version number and exit

Feel free to adapt to your needs.
