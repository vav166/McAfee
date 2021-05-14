#!/usr/bin/python

#ELM_extractor, McAfee Raw Logs extractor
#origin - https://github.com/0x8008135/McAfee/blob/master/extract_raw_logs.py

from datetime import datetime, timedelta as td
import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib as ul

def check_dir(p):
    if not os.path.exists(p):
        os.makedirs(p)


def elm_search(findregex,starttime,endtime,deltatime,workdir,logfile):
    cnt = 0
    st = int(time.mktime(starttime.timetuple()))
    et = int(time.mktime(endtime.timetuple()))
    mt = st
    while mt < et :
        st = int(time.mktime((starttime + td(seconds=deltatime*cnt)).timetuple()))
        mt = int(time.mktime((starttime + td(seconds=deltatime*(cnt+1))).timetuple()))
        wd = workdir + str(st) + "_"  + str(mt) + "/"
        check_dir(wd)
        
        #original command
        #%5E%2E%2A%24 = ^.*$
        #comm = "/usr/local/bin/elmsearch wd=" + wd + " st=" + str(st) + " et=" + str(mt) + " nr=/%5E%2E%2A%24/e mr=/" + findregex + "/ mb=1024" 
        
        #modified
        comm = "/usr/local/bin/elmsearch wd=" + wd + " st=" + str(st) + " et=" + str(mt) + " nr=/%5E%2E%2A%24/e mr=/" + findregex + "/" 
        
        print comm

        logfile.write(comm)

        #original command
        #subprocess.call(["/usr/local/bin/elmsearch", "wd=" + wd, "st=" + str(st), "et=" + str(mt), "nr=/%5E%2E%2A%24/e", "mr=/" + findregex + "/", "mb=1024" ], stdout=l)
        #modified
        subprocess.call(["/usr/local/bin/elmsearch", "wd=" + wd, "st=" + str(st), "et=" + str(mt), "nr=/%5E%2E%2A%24/e", "mr=/" + findregex + "/"], stdout=logfile)

        cnt+=1


if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="Raw log extractor for McAfee ESM")
    parser.add_argument("-l",  action='store', dest="l",  type=str, default="elmlog.txt",   help="Path to log file")
    parser.add_argument("-d",  action='store', dest="d",  type=str, required=True,          help="Temporary directory /ss1/usr/local/elm/tmp/")
    parser.add_argument("-st", action='store', dest="st", type=int, required=True,          help="Start Time (Unix Timestamp)")
    parser.add_argument("-et", action='store', dest="et", type=int, required=True,          help="End Time (Unix Timestamp)")
    parser.add_argument("-mr", action='store', dest="mr", type=str, required=True,          help="Pattern (Posix regexp surrounded with double quotes)")
    parser.add_argument("-sd", action='store', dest="sd", type=int, default=0,              help="Slice in days (stacks with sh,sm,ss)")
    parser.add_argument("-sh", action='store', dest="sh", type=int, default=0,              help="Slice in hours (stacks with sd,sm,ss)")
    parser.add_argument("-sm", action='store', dest="sm", type=int, default=0,              help="Slice in minutes (stacks with sd,sh,ss)")
    parser.add_argument("-ss", action='store', dest="ss", type=int, default=0,              help="Slice in seconds (stacks with sd,sh,sm)")
    args = parser.parse_args()

    st=0
    et=0

    # Check if start date before end date
    if args.st >= args.et :
        print "Start Date must be before End Date"
        exit()

    st=datetime.fromtimestamp(args.st)
    et=datetime.fromtimestamp(args.et)

    # Calculation of delta
    delta=td()
    if 0 <= args.sd <= 31 :
        delta += td(days=args.sd)
    else :
        print "Number of days should be between 1 and 31"
    if 0 <= args.sh <= 23 :
        delta += td(hours=args.sh)
    else :
        print "Number of hours should be between 1 and 23"
    if 0 <= args.sm <= 59 :
        delta += td(minutes=args.sm)
    else :
        print "Number of minutes should be between 1 and 59"
    if 0 <= args.ss <= 59 :
        delta += td(seconds=args.ss)
    else :
        print "Number of seconds should be between 1 and 59"

    if delta == td():
        delta += td(hours=1)
        print "WARNING : No slice defined !! Final result could be truncated (using 1 hour as default)"

    if hasattr(delta, "total_seconds"):
        de = int(delta.total_seconds())
    else:
        de = (delta.seconds + delta.days * 24 * 3600)

    # Working directory
    wd = "/elm_storage/local/tmp/" + args.d + "/"

	# Check if directory exists
    if not os.path.exists(wd):
        # Create directory
        os.makedirs(wd)
    else:
        # Ask if the directory should be deleted
        print "Directory already exists, maybe you would like to empty it ?"
        c = ''
        while c not in ['Y','y','N','n']:
            # Catch single characters
            c = raw_input('Enter Y / N \n')[:1]
        if c in ['y','Y']:
            # Remove directory recursively
            shutil.rmtree(wd)
        else:
            # Do not remove the directory
            print "Directory will not be removed but content can be overwritten"

    # Encode the regexp
    f_regex = ul.quote(args.mr)

	# Open logfile descriptor
    lf = open(args.l,"w")

    elm_search(f_regex, st, et, de, wd, lf)

    lf.close()

    print "\n"
    print "\n"
    print "Please review the log file (" + args.l + ") to see if your results where truncated or not..."
    print "\n"
    print "\n"
    print "To merge results :"
    print "\n"
    print "Change directory to " + wd
    print "\n"
    print "Run the following command : find . -name \"result.txt\" | sort | xargs cat > results.txt"
    print "\n"
    print "Don't forget to cleanup your mess when you are finished !!!!"
    print "\n"
    
    
# elmsearch --help
"""
elmsearch 2014.10.07.10.39

elmsearch is an ELM job executable.  It uses the 'elm' executable,
and an elmjob*search.sh script, to search for logs that match given constraints.

Usage: elmsearch wd=<a> [kd=<b>] [ids=<c>] [st=<d>] [et=<e>] [nr=<f>] \
                 [mb=<g>] [nowTime=<h>] [mr=<i>] [debug=<j>] [onlyfiles=<k>] \
                 [timing=<l>]

Where: a = The work directory.  This directory will be created, if it
           does not exists.
       b = Optional.  The keep directory.  If this value is specified
           it will be created, if it does not exist, and any ASCII or
           BINARY log files that contain matches will be left here.  Any
           files left here will be named 'keep_N', where 'N' is an
           incrementing number starting at one.  If this value is not
           specified no files will be kept.
       c = Optional.  This is the name only of a file within the
           "wd" directory that contains a list, one value per line,
           of the DsrcIDs associated with logs to be considered during
           the search.  If this parameter is not specified no DsrcID
           constraints will be imposed.
       d = Optional.  Only log files containing logs at or after
           this time will be searched.  If this value is not specified
           no lower time limit will be imposed.
       e = Optional.  Only log files containing logs at or before
           this time will be searched.  If this value is not specified
           no upper time limit will be imposed.
       f = Optional. The regular expression that a qualifying logfile's
           name must match. The format of this value is
           '/<regex>/[i|I][v|V][e|E]'; forward slash, regular
           expression, forward slash, an optional 'i', or 'I',
           indicating that the match should ignore character case,
           an optional 'v' or 'V', indicating that the sense of
           the match should be inverted, and an optional 'e' or
           'E', indicating that all ELM files match.  If fileNameRegex
           is '/[<white space>]/[i|I][v|V]' all file names will match.
           If fileNameRegex is '/[<white   space>]/[i|I][v|V][e|E]'
           all ELM files will match.  Any character sequences within
           <regex> of the form "%XX", where "XX" is a string representation
           of two hex digits, will be translated to the character
           equivalent of the two hex digits (e.g. %20 is a space).
       g = Optional.  The maximum number of MB of output allowed.
           When the number of result bytes plus the number of bytes
           in all files saved in 'kd' reach this amount the program
           will terminate.  If this value is not specified no output
           constraint will be imposed.  Note that there is an internal
           limit of 2GB on the number of result bytes.
       h = Optional.  If this value is specified it will be used instead
           of "now", to decide if a requested logfile is within the bounds
           of its retention period.  A value is usually only specified
           for QA tests.
       i = Optional.  The regex that a log must match.  If this value
           is not specified no log regex matching will be imposed.  The
           format of this value is '/<regex>/[i|I][v|V]'; forward slash,
           regular expression, forward slash, an optional 'i', or 'I',
           indicating that the match should ignore character case, and.
           an optional 'v', or 'V', indicating that the sense of the
           match should be inverted.  Any character sequences within
           <regex> of the form "%XX", where "XX" is a string representation
           of two hex digits, will be translated to the character
           equivalent of the two hex digits (e.g. %20 is a space).
       j = Optional.  If this value is "true" developer debug information
           will be generated during execution.
       k = Optional.  If this value is "true", file list will be built
           but no search will be done.
       l = Optional.  If this value is "true" then output timing information
           for get_logfile, elmlfcat and grep to stdout.

First the program will use 'elm cmd=elmd.list_logfiles_bloom_match(...)'
(or 'elm cmd=elmd.list_logfiles(...)') along with the values of the
'ids', 'st', 'et' and 'nr' parameters to generate a list of log
files to be searched.  Next the program will process each list entry using
'elm cmd=elmd.get_logfile(...)' to get the file, and then search the
file for logs matching the 'mr' pattern.  If matching logs are found
they will be written to the result file, a file named 'result.txt'
in the 'wd', with the following format:

  dsrcid,logid,type,time,filename,keep_filename,url_encoded_log

where dsrcid          = The DsrcID associated with the log.
      logid           = The LOGID of the log.
      type            = The log type 'ELM', 'ASCII' or 'BINARY'.
      time            = The log's LOGTIME.
      filename        = The file name for 'ASCII' or 'BINARY' files, or blank
                        for 'ELM' files.
      keep_filename   = For 'ASCII' or 'BINARY' files, the file name within
                        the keep directory of the file that contains the log.
                        If not keeping files, or an 'ELM' log file, this
                        value will be blank.
      url_encoded_log = The log entry itself, URL encoded, for 'ELM' and
                        'ASCII' only, file size for 'BINARY'.

During execution, the program will generate status lines to stdout of the
following format:

  status,info,outlines,outmb,total_files,processed_files,percent_complete

where status           = The execution status.  Values include 'RUNNING',
                         which means the program is running, 'FAILED'
                         which means the program failed to execute,
                         'COMPLETE' which means the program completed
                         normally, and 'DONE', which means the program
                         completed execution early because the total amount
                         of allowed output was reached.
      info             = If status is 'failed' this will specify the reason
                         for the failure, otherwise it will be blank.
      outlines         = The number of lines written to 'os'.
      outmb            = The number of MB of output.
      total_files      = The total number of files to be processed.
      processed_files  = The number of files processed.
      percent_complete = The estimated percent complete.

"""