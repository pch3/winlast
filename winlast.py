#!/usr/bin/env python

from lxml import etree
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from datetime import datetime
from dateutil import tz
from operator import itemgetter
import sys
import argparse
import signal

VERSION = "0.6"


def total_records(args):
    try:
        if not args.quiet:
            sys.stderr.write("Calculating total number of records... ")
        total = 0
        with Evtx(args.evtx) as evtx:
            fh = evtx.get_file_header()
            for chunk in fh.chunks():
                first_record = chunk.log_first_record_number()
                last_record = chunk.log_last_record_number()
                total += 1 + last_record - first_record
            if not args.quiet:
                sys.stderr.write(str(total) + "\n")
            return total
    except IOError as e:
        sys.stderr.write("Error: Cannot open file {}\n".format(filename))
        sys.exit(2)


def xml_records(filename):
    try:
        with Evtx(filename) as evtx:
            for xml, record in evtx_file_xml_view(evtx.get_file_header()):
                try:
                    yield etree.fromstring(xml), None
                except etree.XMLSyntaxError as e:
                    yield xml, e
    except IOError as e:
        sys.stderr.write("Error: Cannot open file {}\n".format(filename))
        sys.exit(2)


def get_child(node, tag,
              ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.find("%s%s" % (ns, tag))


def get_childs(node, tag,
               ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.findall("%s%s" % (ns, tag))


def new_logon_entry():
    return {
        "login": "-",
        "logoff": "-",
        "duration": "?",
        "user": "?",
        "id": "?",
        "type": "?",
        "src": "-:-",
        "sub": []
    }


def compute_duration(login, logoff):
    if login == "-" or logoff == "-":
        return "?"
    return int(
        (datetime.strptime(logoff[:19], "%Y-%m-%d %H:%M:%S") -
         datetime.strptime(login[:19], "%Y-%m-%d %H:%M:%S")).total_seconds()
    )


def format_duration(s):
    if s == "?":
        r = "?"
    else:
        r = ""
        duration = int(s)
        if duration >= 86400:
            r += "{}d".format(int(duration / 86400))
            duration = duration % 86400
        if duration >= 3600:
            r += "{}h".format(int(duration / 3600))
            duration = duration % 3600
        if duration >= 60:
            r += "{}m".format(int(duration / 60))
            duration = duration % 60
        r += "{}s".format(duration)
    return r


def format_logontype(logontype):
    logon_types = {
        "0": "SystemOnly",
        "2": "Interactive",
        "3": "Network",
        "4": "Batch",
        "5": "Service",
        "6": "Proxy",
        "7": "Unlock",
        "8": "NetClearText",
        "9": "NewCred",
        "10": "RemoteI",
        "11": "CachedI",
        "12": "CachedRI",
        "13": "CachedU"
    }
    return logon_types.get(logontype, '?')


def convert_to_localtime(dt, timezone):
    if dt != "-":
        utc = datetime.strptime(
            dt[:19], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=tz.tzutc())
        return utc.astimezone(tz.gettz(timezone)) \
                  .strftime("%Y-%m-%d %H:%M:%S")
    else:
        return "-"


def check_timezone(timezone):
    if tz.gettz(timezone) == None:
        sys.stderr.write(
            "Timezone not recognized. Please use zoneinfo TZ format"
            ", e.g. Europe/Warsaw\n"
        )
        sys.stderr.write(
            "https://en.wikipedia.org/wiki/List_of_tz_database_time_zones\n"
        )
        sys.exit(1)


def print_results(result, args):
    if args.output_format == "csv":
        row_formated = u"{},{},{},{},{},{}\n"
    elif args.output_format == "csv_tab":
        row_formated = u"{}\t{}\t{}\t{}\t{}\t{}\n"
    else:
        row_formated = u"{:30} {:20} {:20} {:>14} {:>12} {:21}\n"
    if args.outfile:
        try:
            output = open(args.outfile, "w")
        except IOError:
            sys.stderr.write("Cannot open file {} for writing!\n"
                             .format(args.outfile))
            output = sys.stdout
    else:
        output = sys.stdout
    output.write(row_formated
                 .format("User", "Login", "Logoff", "Duration", "Type", "Src"))
    for (key, entry) in sorted(result.iteritems(),
                               key=lambda(x, y): y[args.sort_type]):
        if args.tz:
            entry["login"] = convert_to_localtime(entry["login"], args.tz)
            entry["logoff"] = convert_to_localtime(entry["logoff"], args.tz)
        if not args.dc_duration:
            entry["duration"] = format_duration(entry["duration"])
        if not args.dc_type:
            entry["type"] = format_logontype(entry["type"])
        output.write(row_formated.format(entry["user"],
                                         entry["login"],
                                         entry["logoff"],
                                         entry["duration"],
                                         entry["type"],
                                         entry["src"]))
        if not args.sub:
            if args.tz:
                for e in entry["sub"]:
                    e["time"] = convert_to_localtime(e["time"],
                                                     args.tz)
            l = len(entry["sub"])
            for i in range(0, len(entry["sub"]), 2):
                if entry["sub"][i]["stype"] == "Disconnect":
                    if i == 0:
                        login = entry["login"]
                        typ = "Logon/Dis"
                    else:
                        login = entry["sub"][i-1]["time"]
                        typ = "Rec/Dis"
                    logoff = entry["sub"][i]["time"]
                else:
                    if i+1 < l:
                        logoff = entry["sub"][i+1]["time"]
                        typ = "Rec/Dis"
                    else:
                        logoff = entry["logoff"]
                        typ = "Rec/Logoff"
                    login = entry["sub"][i]["time"]
                duration = compute_duration(login, logoff)
                if not args.dc_duration:
                    duration = format_duration(duration)
                output.write(row_formated.format("",
                                                 login,
                                                 logoff,
                                                 duration,
                                                 typ,
                                                 entry["sub"][i]["src"]))
    output.close()


def main():
    parser = argparse.ArgumentParser(
        description="Extract Logon/Logoff events from EVTX files",
        prog="winlast.py"
    )
    parser.add_argument(
        "evtx", type=str, action="store",
        help="Path to the Windows EVTX file"
    )
    parser.add_argument(
        "-z", type=str, action="store", dest="tz",
        help="Convert UTC timestamps to timezone, e.g. 'Europe/Warsaw'"
    )
    parser.add_argument(
        "-d", action="store_true", dest="dc_duration",
        help="Print duration in seconds"
    )
    parser.add_argument(
        "-n", action="store_true", dest="dc_type",
        help="Print numeric logon type"
    )
    parser.add_argument(
        "-f", type=str, action="store", dest="output_format", default="table",
        help="Output format", choices=("table", "csv", "csv_tab")
    )
    parser.add_argument(
        "-u", action="store_true", dest="sub",
        help="Do not print disconnect/reconnect events"
    )
    parser.add_argument(
        "-o", type=str, action="store", dest="outfile",
        help="Write results to file"
    )
    parser.add_argument(
        "-s", type=str, action="store", dest="sort_type",
        help="Sort by...", default="login",
        choices=("login", "logoff", "user", "duration", "type", "src"))
    parser.add_argument(
        "-q", action="store_true", dest="quiet",
        help="Suppress all normal output"
    )
    parser.add_argument(
        "-v", action="version",
        version="%(prog)s by Piotr Chmylkowski ver. {}".format(VERSION)
    )
    args = parser.parse_args()

    def signal_handler(signum, frame):
        if not args.quiet:
            sys.stderr.write("\r\nAborting...\n\033[?25h")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    if args.tz:
        check_timezone(args.tz)
    last = {}
    counter = 0
    if not args.quiet:
        sys.stderr.write("\033[?25l")
    total = total_records(args)
    for node, err in xml_records(args.evtx):
        counter += 1
        if err is not None:
            if not args.quiet:
                sys.stderr.write("Error: " + str(err) + "\n")
            continue
        syst = get_child(node, "System")
        eid = int(get_child(syst, "EventID").text)
        if not args.quiet:
            sys.stderr.write("Processing record no {} ({}%)\r"
                             .format(counter, int(counter*100/total)))
        if eid in (528, 538, 551, 682, 683, 4624, 4634, 4647, 4778, 4779):
            # logon
            if eid == 528:
                entry = new_logon_entry()
                dat = get_child(get_child(node, "EventData"), "Data")
                entry["login"] = \
                    get_child(syst, "TimeCreated").get("SystemTime")
                dupa = "<dupa>"+dat.text.strip()+"</dupa>"
                strs = etree.fromstring(dupa).getchildren()
                entry["user"] = \
                    strs[1].text.upper() + "\\" + strs[0].text.upper()
                entry["id"] = strs[2].text
                entry["type"] = strs[3].text
                if len(strs) > 13:
                    entry["src"] = strs[13].text + ":" + strs[14].text
                key = entry["user"] + entry["id"]
                last[key] = entry
            # logon
            elif eid == 4624:
                entry = new_logon_entry()
                dat = get_childs(get_child(node, "EventData"), "Data")
                entry["login"] = \
                    get_child(syst, "TimeCreated").get("SystemTime")[:19]
                entry["user"] = \
                    dat[6].text.upper() + "\\" + dat[5].text.upper()
                entry["id"] = dat[7].text
                entry["type"] = dat[8].text
                entry["src"] = dat[18].text + ":" + dat[19].text
                key = entry["user"] + entry["id"]
                last[key] = entry
            # logoff
            elif eid == 538 or eid == 551:
                entry = new_logon_entry()
                dat = get_child(get_child(node, "EventData"), "Data")
                entry["logoff"] = \
                    get_child(syst, "TimeCreated").get("SystemTime")
                dupa = "<dupa>"+dat.text.strip()+"</dupa>"
                strs = etree.fromstring(dupa).getchildren()
                entry["user"] = \
                    strs[1].text.upper() + "\\" + strs[0].text.upper()
                entry["id"] = strs[2].text
                key = entry["user"] + entry["id"]
                if key not in last:
                    last[key] = entry
                else:
                    if last[key]["logoff"] == "-":
                        last[key]["logoff"] = entry["logoff"]
                    last[key]["duration"] = compute_duration(
                        last[key]["login"],
                        last[key]["logoff"]
                    )
            # logoff
            elif eid == 4634 or eid == 4647:
                entry = new_logon_entry()
                dat = get_childs(get_child(node, "EventData"), "Data")
                entry["logoff"] = \
                    get_child(syst, "TimeCreated").get("SystemTime")[:19]
                entry["user"] = \
                    dat[2].text.upper() + "\\" + dat[1].text.upper()
                entry["id"] = dat[3].text
                key = entry["user"] + entry["id"]
                if key not in last:
                    last[key] = entry
                else:
                    if last[key]["logoff"] == "-":
                        last[key]["logoff"] = entry["logoff"]
                    last[key]["duration"] = compute_duration(
                        last[key]["login"],
                        last[key]["logoff"]
                    )
            # reconnect
            elif eid == 4778:
                e = {}
                e["stype"] = "Reconnect"
                e["time"] = \
                    get_child(syst, "TimeCreated").get("SystemTime")[:19]
                dat = get_childs(get_child(node, "EventData"), "Data")
                e["src"] = dat[5].text  # + "(" + dat[4].text + ")"
                key = dat[1].text.upper() + "\\" + dat[0].text.upper() + \
                    dat[2].text
                if key in last:
                    last[key]["sub"].append(e)
            # reconnect
            elif eid == 682:
                e = {}
                e["stype"] = "Reconnect"
                e["time"] = get_child(syst, "TimeCreated").get("SystemTime")
                dat = get_child(get_child(node, "EventData"), "Data")
                dupa = "<dupa>"+dat.text.strip()+"</dupa>"
                strs = etree.fromstring(dupa).getchildren()
                e["src"] = strs[5].text  # + "(" + strs[4].text + ")"
                key = strs[1].text.upper() + "\\" + strs[0].text.upper() + \
                    strs[2].text
                if key in last:
                    last[key]["sub"].append(e)
            # disconnect
            elif eid == 4779:
                e = {}
                e["stype"] = "Disconnect"
                e["time"] = \
                    get_child(syst, "TimeCreated").get("SystemTime")[:19]
                dat = get_childs(get_child(node, "EventData"), "Data")
                e["src"] = dat[5].text  # + "(" + dat[4].text + ")"
                key = dat[1].text.upper() + "\\" + dat[0].text.upper() + \
                    dat[2].text
                if key in last:
                    last[key]["sub"].append(e)
            # disconnect
            elif eid == 683:
                e = {}
                e["stype"] = "Disconnect"
                e["time"] = get_child(syst, "TimeCreated").get("SystemTime")
                dat = get_child(get_child(node, "EventData"), "Data")
                dupa = "<dupa>"+dat.text.strip()+"</dupa>"
                strs = etree.fromstring(dupa).getchildren()
                e["src"] = strs[5].text  # + "(" + strs[4].text + ")"
                key = strs[1].text.upper() + "\\" + strs[0].text.upper() + \
                    strs[2].text
                if key in last:
                    last[key]["sub"].append(e)
    if not args.quiet:
        sys.stderr.write("\r\nWriting results...\n\033[?25h")
    print_results(last, args)


if __name__ == "__main__":
    main()
