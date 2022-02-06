// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS.tools;

import java.util.Iterator;
import net.posick.DNS.Name;
import net.posick.DNS.RRset;
import net.posick.DNS.Zone;

public class primary {

  private static void usage() {
    System.out.println("usage: primary [-t] [-a | -i] origin file");
    System.exit(1);
  }

  public static void main(String[] args) throws Exception {
    boolean time = false;
    boolean axfr = false;
    boolean iterator = false;
    int arg = 0;

    if (args.length < 2) {
      usage();
    }

    while (args.length - arg > 2) {
      switch (args[0]) {
        case "-t":
          time = true;
          break;
        case "-a":
          axfr = true;
          break;
        case "-i":
          iterator = true;
          break;
      }
      arg++;
    }

    Name origin = Name.fromString(args[arg++], Name.root);
    String file = args[arg++];

    long start = System.currentTimeMillis();
    Zone zone = new Zone(origin, file);
    long end = System.currentTimeMillis();
    if (axfr) {
      Iterator<RRset> it = zone.AXFR();
      while (it.hasNext()) {
        System.out.println(it.next());
      }
    } else if (iterator) {
      Iterator<RRset> it = zone.iterator();
      while (it.hasNext()) {
        System.out.println(it.next());
      }
    } else {
      System.out.println(zone);
    }
    if (time) {
      System.out.println("; Load time: " + (end - start) + " ms");
    }
  }
}
