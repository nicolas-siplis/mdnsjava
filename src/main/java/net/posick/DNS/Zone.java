// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.DClass;
import net.posick.DNS.Master;
import net.posick.DNS.Name;
import net.posick.DNS.RRSIGRecord;
import net.posick.DNS.RRset;
import net.posick.DNS.Record;
import net.posick.DNS.SOARecord;
import net.posick.DNS.SetResponse;
import net.posick.DNS.Type;
import net.posick.DNS.ZoneTransferException;
import net.posick.DNS.ZoneTransferIn;

import java.io.IOException;
import java.io.Serializable;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.TreeMap;

/**
 * A DNS Zone. This encapsulates all data related to a Zone, and provides convenient lookup methods.
 *
 * @author Brian Wellington
 */
public class Zone implements Serializable {

  private static final long serialVersionUID = -9220510891189510942L;

  /** A primary zone */
  public static final int PRIMARY = 1;

  /** A secondary zone */
  public static final int SECONDARY = 2;

  private Map<net.posick.DNS.Name, Object> data;
  private net.posick.DNS.Name origin;
  private Object originNode;
  private net.posick.DNS.RRset NS;
  private net.posick.DNS.SOARecord SOA;
  private boolean hasWild;

  class ZoneIterator implements Iterator<net.posick.DNS.RRset> {
    private final Iterator<Map.Entry<net.posick.DNS.Name, Object>> zentries;
    private net.posick.DNS.RRset[] current;
    private int count;
    private boolean wantLastSOA;

    ZoneIterator(boolean axfr) {
      synchronized (Zone.this) {
        zentries = data.entrySet().iterator();
      }
      wantLastSOA = axfr;
      net.posick.DNS.RRset[] sets = allRRsets(originNode);
      current = new net.posick.DNS.RRset[sets.length];
      for (int i = 0, j = 2; i < sets.length; i++) {
        int type = sets[i].getType();
        if (type == net.posick.DNS.Type.SOA) {
          current[0] = sets[i];
        } else if (type == net.posick.DNS.Type.NS) {
          current[1] = sets[i];
        } else {
          current[j++] = sets[i];
        }
      }
    }

    @Override
    public boolean hasNext() {
      return current != null || wantLastSOA;
    }

    @Override
    public net.posick.DNS.RRset next() {
      if (!hasNext()) {
        throw new NoSuchElementException();
      }
      if (current == null) {
        wantLastSOA = false;
        return oneRRset(originNode, net.posick.DNS.Type.SOA);
      }
      net.posick.DNS.RRset set = current[count++];
      if (count == current.length) {
        current = null;
        while (zentries.hasNext()) {
          Map.Entry<net.posick.DNS.Name, Object> entry = zentries.next();
          if (entry.getKey().equals(origin)) {
            continue;
          }
          net.posick.DNS.RRset[] sets = allRRsets(entry.getValue());
          if (sets.length == 0) {
            continue;
          }
          current = sets;
          count = 0;
          break;
        }
      }
      return set;
    }

    @Override
    public void remove() {
      throw new UnsupportedOperationException();
    }
  }

  private void validate() throws IOException {
    originNode = exactName(origin);
    if (originNode == null) {
      throw new IOException(origin + ": no data specified");
    }

    net.posick.DNS.RRset rrset = oneRRset(originNode, net.posick.DNS.Type.SOA);
    if (rrset == null || rrset.size() != 1) {
      throw new IOException(origin + ": exactly 1 SOA must be specified");
    }
    SOA = (net.posick.DNS.SOARecord) rrset.rrs().get(0);

    NS = oneRRset(originNode, net.posick.DNS.Type.NS);
    if (NS == null) {
      throw new IOException(origin + ": no NS set specified");
    }
  }

  private void maybeAddRecord(net.posick.DNS.Record record) throws IOException {
    int rtype = record.getType();
    net.posick.DNS.Name name = record.getName();

    if (rtype == net.posick.DNS.Type.SOA && !name.equals(origin)) {
      throw new IOException("SOA owner " + name + " does not match zone origin " + origin);
    }
    if (name.subdomain(origin)) {
      addRecord(record);
    }
  }

  /**
   * Creates a Zone from the records in the specified master file.
   *
   * @param zone The name of the zone.
   * @param file The master file to read from.
   * @see Master
   */
  public Zone(net.posick.DNS.Name zone, String file) throws IOException {
    data = new TreeMap<>();

    if (zone == null) {
      throw new IllegalArgumentException("no zone name specified");
    }
    try (Master m = new Master(file, zone)) {
      net.posick.DNS.Record record;

      origin = zone;
      while ((record = m.nextRecord()) != null) {
        maybeAddRecord(record);
      }
    }
    validate();
  }

  /**
   * Creates a Zone from an array of records.
   *
   * @param zone The name of the zone.
   * @param records The records to add to the zone.
   * @see Master
   */
  public Zone(net.posick.DNS.Name zone, net.posick.DNS.Record[] records) throws IOException {
    data = new TreeMap<>();

    if (zone == null) {
      throw new IllegalArgumentException("no zone name specified");
    }
    origin = zone;
    for (net.posick.DNS.Record record : records) {
      maybeAddRecord(record);
    }
    validate();
  }

  private void fromXFR(net.posick.DNS.ZoneTransferIn xfrin) throws IOException, net.posick.DNS.ZoneTransferException {
    synchronized (this) {
      data = new TreeMap<>();
    }

    origin = xfrin.getName();
    xfrin.run();
    if (!xfrin.isAXFR()) {
      throw new IllegalArgumentException("zones can only be created from AXFRs");
    }

    for (net.posick.DNS.Record record : xfrin.getAXFR()) {
      maybeAddRecord(record);
    }
    validate();
  }

  /**
   * Creates a Zone by doing the specified zone transfer.
   *
   * @param xfrin The incoming zone transfer to execute.
   * @see net.posick.DNS.ZoneTransferIn
   */
  public Zone(net.posick.DNS.ZoneTransferIn xfrin) throws IOException, net.posick.DNS.ZoneTransferException {
    fromXFR(xfrin);
  }

  /**
   * Creates a Zone by performing a zone transfer to the specified host.
   *
   * @see net.posick.DNS.ZoneTransferIn
   */
  public Zone(net.posick.DNS.Name zone, int dclass, String remote) throws IOException, ZoneTransferException {
    net.posick.DNS.ZoneTransferIn xfrin = ZoneTransferIn.newAXFR(zone, remote, null);
    xfrin.setDClass(dclass);
    fromXFR(xfrin);
  }

  /** Returns the Zone's origin */
  public net.posick.DNS.Name getOrigin() {
    return origin;
  }

  /** Returns the Zone origin's NS records */
  public net.posick.DNS.RRset getNS() {
    return NS;
  }

  /** Returns the Zone's SOA record */
  public SOARecord getSOA() {
    return SOA;
  }

  /** Returns the Zone's class */
  public int getDClass() {
    return DClass.IN;
  }

  private synchronized Object exactName(net.posick.DNS.Name name) {
    return data.get(name);
  }

  private synchronized net.posick.DNS.RRset[] allRRsets(Object types) {
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<net.posick.DNS.RRset> typelist = (List<net.posick.DNS.RRset>) types;
      return typelist.toArray(new net.posick.DNS.RRset[0]);
    } else {
      net.posick.DNS.RRset set = (net.posick.DNS.RRset) types;
      return new net.posick.DNS.RRset[] {set};
    }
  }

  private synchronized net.posick.DNS.RRset oneRRset(Object types, int type) {
    if (type == net.posick.DNS.Type.ANY) {
      throw new IllegalArgumentException("oneRRset(ANY)");
    }
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<net.posick.DNS.RRset> list = (List<net.posick.DNS.RRset>) types;
      for (net.posick.DNS.RRset set : list) {
        if (set.getType() == type) {
          return set;
        }
      }
    } else {
      net.posick.DNS.RRset set = (net.posick.DNS.RRset) types;
      if (set.getType() == type) {
        return set;
      }
    }
    return null;
  }

  private synchronized net.posick.DNS.RRset findRRset(net.posick.DNS.Name name, int type) {
    Object types = exactName(name);
    if (types == null) {
      return null;
    }
    return oneRRset(types, type);
  }

  private synchronized void addRRset(net.posick.DNS.Name name, net.posick.DNS.RRset rrset) {
    if (!hasWild && name.isWild()) {
      hasWild = true;
    }
    Object types = data.get(name);
    if (types == null) {
      data.put(name, rrset);
      return;
    }
    int rtype = rrset.getType();
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<net.posick.DNS.RRset> list = (List<net.posick.DNS.RRset>) types;
      for (int i = 0; i < list.size(); i++) {
        net.posick.DNS.RRset set = list.get(i);
        if (set.getType() == rtype) {
          list.set(i, rrset);
          return;
        }
      }
      list.add(rrset);
    } else {
      net.posick.DNS.RRset set = (net.posick.DNS.RRset) types;
      if (set.getType() == rtype) {
        data.put(name, rrset);
      } else {
        LinkedList<net.posick.DNS.RRset> list = new LinkedList<>();
        list.add(set);
        list.add(rrset);
        data.put(name, list);
      }
    }
  }

  private synchronized void removeRRset(net.posick.DNS.Name name, int type) {
    Object types = data.get(name);
    if (types == null) {
      return;
    }
    if (types instanceof List) {
      @SuppressWarnings("unchecked")
      List<net.posick.DNS.RRset> list = (List<net.posick.DNS.RRset>) types;
      for (int i = 0; i < list.size(); i++) {
        net.posick.DNS.RRset set = list.get(i);
        if (set.getType() == type) {
          list.remove(i);
          if (list.size() == 0) {
            data.remove(name);
          }
          return;
        }
      }
    } else {
      net.posick.DNS.RRset set = (net.posick.DNS.RRset) types;
      if (set.getType() != type) {
        return;
      }
      data.remove(name);
    }
  }

  private synchronized net.posick.DNS.SetResponse lookup(net.posick.DNS.Name name, int type) {
    if (!name.subdomain(origin)) {
      return net.posick.DNS.SetResponse.ofType(net.posick.DNS.SetResponse.NXDOMAIN);
    }

    int labels = name.labels();
    int olabels = origin.labels();

    for (int tlabels = olabels; tlabels <= labels; tlabels++) {
      boolean isOrigin = tlabels == olabels;
      boolean isExact = tlabels == labels;

      net.posick.DNS.Name tname;
      if (isOrigin) {
        tname = origin;
      } else if (isExact) {
        tname = name;
      } else {
        tname = new net.posick.DNS.Name(name, labels - tlabels);
      }

      Object types = exactName(tname);
      if (types == null) {
        continue;
      }

      /* If this is a delegation, return that. */
      if (!isOrigin) {
        net.posick.DNS.RRset ns = oneRRset(types, net.posick.DNS.Type.NS);
        if (ns != null) {
          return new net.posick.DNS.SetResponse(net.posick.DNS.SetResponse.DELEGATION, ns);
        }
      }

      /* If this is an ANY lookup, return everything. */
      if (isExact && type == net.posick.DNS.Type.ANY) {
        net.posick.DNS.SetResponse sr = new net.posick.DNS.SetResponse(net.posick.DNS.SetResponse.SUCCESSFUL);
        for (net.posick.DNS.RRset set : allRRsets(types)) {
          sr.addRRset(set);
        }
        return sr;
      }

      /*
       * If this is the name, look for the actual type or a CNAME.
       * Otherwise, look for a DNAME.
       */
      if (isExact) {
        net.posick.DNS.RRset rrset = oneRRset(types, type);
        if (rrset != null) {
          return new net.posick.DNS.SetResponse(net.posick.DNS.SetResponse.SUCCESSFUL, rrset);
        }
        rrset = oneRRset(types, net.posick.DNS.Type.CNAME);
        if (rrset != null) {
          return new net.posick.DNS.SetResponse(net.posick.DNS.SetResponse.CNAME, rrset);
        }
      } else {
        net.posick.DNS.RRset rrset = oneRRset(types, net.posick.DNS.Type.DNAME);
        if (rrset != null) {
          return new net.posick.DNS.SetResponse(net.posick.DNS.SetResponse.DNAME, rrset);
        }
      }

      /* We found the name, but not the type. */
      if (isExact) {
        return net.posick.DNS.SetResponse.ofType(net.posick.DNS.SetResponse.NXRRSET);
      }
    }

    if (hasWild) {
      for (int i = 0; i < labels - olabels; i++) {
        net.posick.DNS.Name tname = name.wild(i + 1);
        Object types = exactName(tname);
        if (types == null) {
          continue;
        }

        if (type == Type.ANY) {
          net.posick.DNS.SetResponse sr = new net.posick.DNS.SetResponse(net.posick.DNS.SetResponse.SUCCESSFUL);
          for (net.posick.DNS.RRset set : allRRsets(types)) {
            sr.addRRset(expandSet(set, name));
          }
          return sr;
        } else {
          net.posick.DNS.RRset rrset = oneRRset(types, type);
          if (rrset != null) {
            return new net.posick.DNS.SetResponse(net.posick.DNS.SetResponse.SUCCESSFUL, expandSet(rrset, name));
          }
        }
      }
    }

    return net.posick.DNS.SetResponse.ofType(net.posick.DNS.SetResponse.NXDOMAIN);
  }

  private net.posick.DNS.RRset expandSet(net.posick.DNS.RRset set, net.posick.DNS.Name tname) {
    net.posick.DNS.RRset expandedSet = new net.posick.DNS.RRset();
    for (net.posick.DNS.Record r : set.rrs()) {
      expandedSet.addRR(r.withName(tname));
    }
    for (RRSIGRecord r : set.sigs()) {
      expandedSet.addRR(r.withName(tname));
    }
    return expandedSet;
  }

  /**
   * Looks up Records in the Zone. The answer can be a {@code CNAME} instead of the actual requested
   * type and wildcards are expanded.
   *
   * @param name The name to look up
   * @param type The type to look up
   * @return A SetResponse object
   * @see net.posick.DNS.SetResponse
   */
  public SetResponse findRecords(net.posick.DNS.Name name, int type) {
    return lookup(name, type);
  }

  /**
   * Looks up Records in the zone, finding exact matches only.
   *
   * @param name The name to look up
   * @param type The type to look up
   * @return The matching RRset
   * @see net.posick.DNS.RRset
   */
  public net.posick.DNS.RRset findExactMatch(net.posick.DNS.Name name, int type) {
    Object types = exactName(name);
    if (types == null) {
      return null;
    }
    return oneRRset(types, type);
  }

  /**
   * Adds an RRset to the Zone
   *
   * @param rrset The RRset to be added
   * @see net.posick.DNS.RRset
   */
  public void addRRset(net.posick.DNS.RRset rrset) {
    net.posick.DNS.Name name = rrset.getName();
    addRRset(name, rrset);
  }

  /**
   * Adds a Record to the Zone
   *
   * @param r The record to be added
   * @see net.posick.DNS.Record
   */
  public <T extends net.posick.DNS.Record> void addRecord(T r) {
    net.posick.DNS.Name name = r.getName();
    int rtype = r.getRRsetType();
    synchronized (this) {
      net.posick.DNS.RRset rrset = findRRset(name, rtype);
      if (rrset == null) {
        rrset = new net.posick.DNS.RRset(r);
        addRRset(name, rrset);
      } else {
        rrset.addRR(r);
      }
    }
  }

  /**
   * Removes a record from the Zone
   *
   * @param r The record to be removed
   * @see net.posick.DNS.Record
   */
  public void removeRecord(Record r) {
    net.posick.DNS.Name name = r.getName();
    int rtype = r.getRRsetType();
    synchronized (this) {
      net.posick.DNS.RRset rrset = findRRset(name, rtype);
      if (rrset == null) {
        return;
      }
      if (rrset.size() == 1 && rrset.first().equals(r)) {
        removeRRset(name, rtype);
      } else {
        rrset.deleteRR(r);
      }
    }
  }

  /** Returns an Iterator over the RRsets in the zone. */
  public Iterator<net.posick.DNS.RRset> iterator() {
    return new ZoneIterator(false);
  }

  /**
   * Returns an Iterator over the RRsets in the zone that can be used to construct an AXFR response.
   * This is identical to {@link #iterator} except that the SOA is returned at the end as well as
   * the beginning.
   */
  public Iterator<net.posick.DNS.RRset> AXFR() {
    return new ZoneIterator(true);
  }

  private void nodeToString(StringBuffer sb, Object node) {
    net.posick.DNS.RRset[] sets = allRRsets(node);
    for (RRset rrset : sets) {
      rrset.rrs().forEach(r -> sb.append(r).append('\n'));
      rrset.sigs().forEach(r -> sb.append(r).append('\n'));
    }
  }

  /** Returns the contents of the Zone in master file format. */
  public synchronized String toMasterFile() {
    StringBuffer sb = new StringBuffer();
    nodeToString(sb, originNode);
    for (Map.Entry<Name, Object> entry : data.entrySet()) {
      if (!origin.equals(entry.getKey())) {
        nodeToString(sb, entry.getValue());
      }
    }
    return sb.toString();
  }

  /** Returns the contents of the Zone as a string (in master file format). */
  @Override
  public String toString() {
    return toMasterFile();
  }
}
