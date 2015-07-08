#!/usr/bin/env python

from lxml import etree
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from datetime import datetime
from dateutil import tz
import sys
import argparse

def xml_records(filename):
    with Evtx(filename) as evtx:
        for xml, record in evtx_file_xml_view(evtx.get_file_header()):
            try:
                yield etree.fromstring(xml), None
            except etree.XMLSyntaxError as e:
                yield xml, e


def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.find("%s%s" % (ns, tag))


def get_childs(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.findall("%s%s" % (ns, tag))


def compute_duration(login, logoff):
    duration = int((datetime.strptime(logoff, "%Y-%m-%d %H:%M:%S") - 
                    datetime.strptime(login, "%Y-%m-%d %H:%M:%S")).total_seconds())
    r = ""
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
    logon_types = { "2":"Interactive", 
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
    return logon_types[logontype]


def convert_to_localtime(dt, timezone):
    utc = datetime.strptime(dt, "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz.tzutc())
    return utc.astimezone(tz.gettz(timezone)).strftime("%Y-%m-%d %H:%M:%S")


def check_timezone(timezone):
    if tz.gettz(timezone) == None:
      print "Timezone not recognized. Please use zoneinfo TZ format, e.g. Europe/Warsaw"
      print "https://en.wikipedia.org/wiki/List_of_tz_database_time_zones"
      sys.exit(1)


def print_results(result, output_format="table"):
    if output_format == "csv":
        row_formated="{},{},{},{},{},{}"
    elif output_format == "csv_tab":
        row_formated="{}\t{}\t{}\t{}\t{}\t{}"
    else:
        row_formated="{:30} {:20} {:20} {:>12} {:>12} {:21}"
    print row_formated.format("User", "Login", "Logoff", "Duration", "Type", "Src")
    for entry in result:
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
    parser.add_argument("-t", "--timezone", type=str, action="store", dest="tz",
                        help="Convert UTC timestamps to timezone, e.g. 'Europe/Warsaw'")
    parser.add_argument("-f", "--format", type=str, action="store", dest="output_format",
                        help="Output format", choices=("table", "csv", "csv_tab"))
    parser.add_argument("-v", "--version", action="version", version="%(prog)s by Piotr Chmylkowski ver. 0.1")
    args = parser.parse_args()
    if args.tz:
        check_timezone(args.tz)
    last = []
    for node, err in xml_records(args.evtx):
        if err is not None:
            continue
        sys = get_child(node, "System")
        dat = get_child(get_child(node, "EventData"), "Data")
        eid = int(get_child(sys, "EventID").text)
        if eid in (528, 538, 551, 4624, 4634, 4647):
            if eid == 528:
                entry = {}
                entry["login"]  = get_child(sys, "TimeCreated").get("SystemTime")
                if args.tz:
                    entry["login"] = convert_to_localtime(entry["login"], args.tz)
                entry["logoff"] = "-"
                entry["duration"] = "?"
                strs = get_childs(dat, "string")
                entry["user"]   = strs[1].text + "\\" + strs[0].text 
                entry["id"]     = strs[2].text
                entry["type"]   = format_logontype(strs[3].text)
                entry["src"]    = "-:-"
                if len(strs) > 13:
                    entry["src"]  = strs[13].text + ":" + strs[14].text
                last.append(entry)
            if eid == 538 or eid == 551:
                entry = {}
                entry["logoff"] = get_child(sys, "TimeCreated").get("SystemTime")            
                strs = get_childs(dat, "string")
                entry["user"]   = strs[1].text + "\\" + strs[0].text 
                entry["id"]     = strs[2].text
                for oldentry in last:
                    if oldentry["user"] == entry["user"] and oldentry["id"] == entry["id"]:
                        oldentry["logoff"] = entry["logoff"]
                        if args.tz:
                           oldentry["logoff"] = convert_to_localtime(oldentry["logoff"], args.tz) 
                        oldentry["duration"] = compute_duration(oldentry["login"], oldentry["logoff"])
                        break
    print_results(last, args.output_format)

if __name__ == "__main__":
    main()

