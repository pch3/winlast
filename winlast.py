#!/usr/bin/env python

# TODO:
# Report RDP connect/diconnect events

from lxml import etree
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from datetime import datetime
from dateutil import tz
from operator import itemgetter
import sys
import argparse


def xml_records(filename):
    try:
        with Evtx(filename) as evtx:
            for xml, record in evtx_file_xml_view(evtx.get_file_header()):
                try:
                    yield etree.fromstring(xml), None
                except etree.XMLSyntaxError as e:
                    yield xml, e
    except IOError as e:
        print "Error: Cannot open file {}".format(filename)
        sys.exit(2)


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.find("%s%s" % (ns, tag))


def get_childs(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.findall("%s%s" % (ns, tag))


def new_logon_entry():
    entry = {}    
    entry["login"]  = "-"
    entry["logoff"] = "-"
    entry["duration"] = "?"
    entry["user"]   = "?"
    entry["id"]     = "?"
    entry["type"]   = "?"
    entry["src"]    = "-:-"
    return entry


def compute_duration(login, logoff):
    if login == "-" or logoff == "-":
        return "?"
    return  int((datetime.strptime(logoff[:19], "%Y-%m-%d %H:%M:%S") - 
                 datetime.strptime(login[:19], "%Y-%m-%d %H:%M:%S")).total_seconds())


def format_duration(s):
    r = ""
    duration = int(s)
    if duration >= 86400:
        r += "{}d".format(int(duration / 86400))
        duration = duration % 86400
    if duration >= 3600:
        r += "{}h".format(int(duration / 3600))
        duration = duration % 3600
    if duration >= 60:
        r+= "{}m".format(int(duration / 60))
        duration = duration % 60
    r += "{}s".format(duration)
    return r


def format_logontype(logontype):
    logon_types = { "0":"System Only",
                    "2":"Interactive", 
                    "3":"Network", 
                    "4":"Batch", 
                    "5":"Service", 
                    "6":"Proxy", 
                    "7":"Unlock", 
                    "8":"NetClearText", 
                    "9":"NewCred", 
                   "10":"RemoteI", 
                   "11":"CachedI",
                   "12":"CachedRI",
                   "13":"CachedU"}
    return logon_types.get(logontype, 'UNKNOWN')


def convert_to_localtime(dt, timezone):
    utc = datetime.strptime(dt[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz.tzutc())
    return utc.astimezone(tz.gettz(timezone)).strftime("%Y-%m-%d %H:%M:%S")


def check_timezone(timezone):
    if tz.gettz(timezone) == None:
      print "Timezone not recognized. Please use zoneinfo TZ format, e.g. Europe/Warsaw"
      print "https://en.wikipedia.org/wiki/List_of_tz_database_time_zones"
      sys.exit(1)


def print_results(result, args):
    if args.output_format == "csv":
        row_formated="{},{},{},{},{},{}"
    elif args.output_format == "csv_tab":
        row_formated="{}\t{}\t{}\t{}\t{}\t{}"
    else:
        row_formated="{:30} {:20} {:20} {:>14} {:>12} {:21}"
    print row_formated.format("User", "Login", "Logoff", "Duration", "Type", "Src")
    for (key, entry) in sorted(result.iteritems(), key=lambda(x, y): y[args.sort_type]):
        if args.tz:
            entry["login"] = convert_to_localtime(entry["login"], args.tz)
            entry["logoff"] = convert_to_localtime(entry["logoff"], args.tz)
        if not args.dc_duration and entry["duration"] != "?":
            entry["duration"] = format_duration(entry["duration"])
        if not args.dc_type:
            entry["type"] = format_logontype(entry["type"])
        print row_formated.format(entry["user"], 
                                  entry["login"], 
                                  entry["logoff"], 
                                  entry["duration"], 
                                  entry["type"], 
                                  entry["src"])


def main():
    parser = argparse.ArgumentParser(
        description = "Extract Logon/Logoff events from EVTX files",
        prog = "winlast.py")
    parser.add_argument("evtx", type=str, action="store", 
                        help="Path to the Windows EVTX file")
    parser.add_argument("-t", type=str, action="store", dest="tz",
                        help="Convert UTC timestamps to timezone, e.g. 'Europe/Warsaw'")
    parser.add_argument("-d", action="store_true", dest="dc_duration",
                        help="Print duration in seconds")
    parser.add_argument("-n", action="store_true", dest="dc_type",
                        help="Print numeric logon type")
    parser.add_argument("-f", type=str, action="store", dest="output_format",
                        help="Output format", choices=("table", "csv", "csv_tab"), default="table")
#    parser.add_argument("-u", "--sub", type=str, action="store", dest="sub",
#                        help="Consider disconnect/reconnect as logoff/login")
    parser.add_argument("-s", type=str, action="store", dest="sort_type",
                        help="Sort by...", choices=("login", "logoff", "user", "duration", "type", "src"), default="login")
    parser.add_argument("-v", action="version", version="%(prog)s by Piotr Chmylkowski ver. 0.2")
    args = parser.parse_args()
    if args.tz:
        check_timezone(args.tz)
    last = {}
    for node, err in xml_records(args.evtx):
        if err is not None:
            continue
        syst = get_child(node, "System")
        eid = int(get_child(syst, "EventID").text)
        print "\033[?25lProcessing EventID={}\r".format(eid),
        if eid in (528, 538, 551, 4624, 4634, 4647):
            # logon 
            if eid == 528:
                entry = new_logon_entry()
                dat = get_child(get_child(node, "EventData"), "Data")
                entry["login"]  = get_child(syst, "TimeCreated").get("SystemTime")
                dupa = "<dupa>"+dat.text.strip()+"</dupa>"
                strs = etree.fromstring(dupa).getchildren()
                entry["user"]   = strs[1].text.upper() + "\\" + strs[0].text.upper()
                entry["id"]     = strs[2].text
                entry["type"]   = strs[3].text
                if len(strs) > 13:
                    entry["src"]  = strs[13].text + ":" + strs[14].text
                key = entry["user"] + entry["id"]
                last[key] = entry
            # logon 
            elif eid == 4624:
                entry = new_logon_entry()
                dat = get_childs(get_child(node, "EventData"), "Data")
                entry["login"]  = get_child(syst, "TimeCreated").get("SystemTime")[:19]
                entry["user"]   = dat[6].text.upper() + "\\" + dat[5].text.upper()
                entry["id"]     = dat[7].text
                entry["type"]   = format_logontype(dat[8].text)
                entry["src"]  = dat[18].text + ":" + dat[19].text
                key = entry["user"] + entry["id"]
                last[key] = entry
            # logoff
            elif eid == 538 or eid == 551:
                entry = new_logon_entry()
                dat = get_child(get_child(node, "EventData"), "Data")
                entry["logoff"] = get_child(syst, "TimeCreated").get("SystemTime")            
                dupa = "<dupa>"+dat.text.strip()+"</dupa>"
                strs = etree.fromstring(dupa).getchildren()
                entry["user"]   = strs[1].text.upper() + "\\" + strs[0].text.upper()
                entry["id"]     = strs[2].text
                key = entry["user"] + entry["id"]
                if not last.has_key(key):
                    last[key] = entry
                else:
                    if last[key]["logoff"] == "-":
                        last[key]["logoff"] = entry["logoff"]
                    last[key]["duration"] = compute_duration(last[key]["login"], last[key]["logoff"])
            # logoff
            elif eid == 4634 or eid == 4647:
                entry = new_logon_entry()
                dat = get_childs(get_child(node, "EventData"), "Data")
                entry["logoff"] = get_child(syst, "TimeCreated").get("SystemTime")[:19]
                entry["user"]   = dat[2].text.upper() + "\\" + dat[1].text.upper()
                entry["id"]     = dat[3].text
                key = entry["user"] + entry["id"]
                if not last.has_key(key):
                    last[key] = entry
                else:
                    if last[key]["logoff"] == "-":
                        last[key]["logoff"] = entry["logoff"]
                    last[key]["duration"] = compute_duration(last[key]["login"], last[key]["logoff"])
    sys.stdout.write("\033[?25h")
    print_results(last, args)

if __name__ == "__main__":
    main()

