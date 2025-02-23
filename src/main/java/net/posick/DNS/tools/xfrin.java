// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS.tools;

import java.util.Iterator;
import net.posick.DNS.Lookup;
import net.posick.DNS.Name;
import net.posick.DNS.Record;
import net.posick.DNS.SimpleResolver;
import net.posick.DNS.TSIG;
import net.posick.DNS.Type;
import net.posick.DNS.ZoneTransferIn;
import net.posick.DNS.ZoneTransferIn.Delta;

public class xfrin {

  private static void usage(String s) {
    System.out.println("Error: " + s);
    System.out.println(
        "usage: xfrin [-i serial] [-k keyname/secret] [-s server] [-p port] [-f] zone");
    System.exit(1);
  }

  public static void main(String[] args) throws Exception {
    ZoneTransferIn xfrin;
    TSIG key = null;
    int ixfr_serial = -1;
    String server = null;
    int port = SimpleResolver.DEFAULT_PORT;
    boolean fallback = false;
    Name zname;

    int arg = 0;
    while (arg < args.length) {
      if (args[arg].equals("-i")) {
        ixfr_serial = Integer.parseInt(args[++arg]);
        if (ixfr_serial < 0) {
          usage("invalid serial number");
        }
      } else if (args[arg].equals("-k")) {
        String s = args[++arg];
        int index = s.indexOf('/');
        if (index < 0) {
          usage("invalid key");
        }
        key = new TSIG(TSIG.HMAC_MD5, s.substring(0, index), s.substring(index + 1));
      } else if (args[arg].equals("-s")) {
        server = args[++arg];
      } else if (args[arg].equals("-p")) {
        port = Integer.parseInt(args[++arg]);
        if (port < 0 || port > 0xFFFF) {
          usage("invalid port");
        }
      } else if (args[arg].equals("-f")) {
        fallback = true;
      } else if (args[arg].startsWith("-")) {
        usage("invalid option");
      } else {
        break;
      }
      arg++;
    }
    if (arg >= args.length) {
      usage("no zone name specified");
    }
    zname = Name.fromString(args[arg]);

    if (server == null) {
      Lookup l = new Lookup(zname, Type.NS);
      Record[] ns = l.run();
      if (ns == null) {
        System.out.println("failed to look up NS record: " + l.getErrorString());
        System.exit(1);
      }
      server = ns[0].rdataToString();
      System.out.println("sending to server '" + server + "'");
    }

    if (ixfr_serial >= 0) {
      xfrin = ZoneTransferIn.newIXFR(zname, ixfr_serial, fallback, server, port, key);
    } else {
      xfrin = ZoneTransferIn.newAXFR(zname, server, port, key);
    }

    xfrin.run();
    if (xfrin.isAXFR()) {
      if (ixfr_serial >= 0) {
        System.out.println("AXFR-like IXFR response");
      } else {
        System.out.println("AXFR response");
      }
      for (Record record : xfrin.getAXFR()) {
        System.out.println(record);
      }
    } else if (xfrin.isIXFR()) {
      System.out.println("IXFR response");
      for (Delta delta : xfrin.getIXFR()) {
        System.out.println("delta from " + delta.start + " to " + delta.end);
        System.out.println("deletes");
        Iterator<Record> it2 = delta.deletes.iterator();
        while (it2.hasNext()) {
          System.out.println(it2.next());
        }
        System.out.println("adds");
        it2 = delta.adds.iterator();
        while (it2.hasNext()) {
          System.out.println(it2.next());
        }
      }
    } else if (xfrin.isCurrent()) {
      System.out.println("up to date");
    }
  }
}
