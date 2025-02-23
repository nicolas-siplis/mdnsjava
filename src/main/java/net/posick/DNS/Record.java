// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import net.posick.DNS.Compression;
import net.posick.DNS.DClass;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Options;
import net.posick.DNS.RRset;
import net.posick.DNS.RelativeNameException;
import net.posick.DNS.SIGBase;
import net.posick.DNS.Section;
import net.posick.DNS.TTL;
import net.posick.DNS.TextParseException;
import net.posick.DNS.Tokenizer;
import net.posick.DNS.Type;
import net.posick.DNS.UNKRecord;
import net.posick.DNS.WireParseException;
import net.posick.DNS.utils.base16;

/**
 * A generic DNS resource record. The specific record types extend this class. A record contains a
 * name, type, class, ttl, and rdata.
 *
 * @author Brian Wellington
 */
@Slf4j
public abstract class Record implements Cloneable, Comparable<Record>, Serializable {
  protected net.posick.DNS.Name name;
  protected int type;
  protected int dclass;
  protected long ttl;

  private static final DecimalFormat byteFormat = new DecimalFormat();

  static {
    byteFormat.setMinimumIntegerDigits(3);
  }

  private static class RecordSerializationProxy implements Serializable {
    private static final long serialVersionUID = 1434159920070152561L;
    private final byte[] wireData;
    private final boolean isEmpty;

    RecordSerializationProxy(Record r) {
      this.isEmpty = r instanceof EmptyRecord;
      wireData = r.toWire(isEmpty ? net.posick.DNS.Section.QUESTION : net.posick.DNS.Section.ANSWER);
    }

    protected Object readResolve() throws ObjectStreamException {
      try {
        return Record.fromWire(wireData, isEmpty ? net.posick.DNS.Section.QUESTION : net.posick.DNS.Section.ANSWER);
      } catch (IOException e) {
        throw new InvalidObjectException(e.getMessage());
      }
    }
  }

  protected Record() {}

  /** @since 3.1 */
  protected Record(net.posick.DNS.Name name, int type, int dclass, long ttl) {
    if (!name.isAbsolute()) {
      throw new RelativeNameException(name);
    }
    Type.check(type);
    DClass.check(dclass);
    net.posick.DNS.TTL.check(ttl);
    this.name = name;
    this.type = type;
    this.dclass = dclass;
    this.ttl = ttl;
  }

  Object writeReplace() {
    log.trace("Creating proxy object for serialization");
    return new RecordSerializationProxy(this);
  }

  private void readObject(ObjectInputStream ois) throws InvalidObjectException {
    throw new InvalidObjectException("Use RecordSerializationProxy");
  }

  private static Record getEmptyRecord(net.posick.DNS.Name name, int type, int dclass, long ttl, boolean hasData) {
    Record rec;
    if (hasData) {
      Supplier<Record> factory = Type.getFactory(type);
      if (factory != null) {
        rec = factory.get();
      } else {
        rec = new UNKRecord();
      }
    } else {
      rec = new EmptyRecord();
    }
    rec.name = name;
    rec.type = type;
    rec.dclass = dclass;
    rec.ttl = ttl;
    return rec;
  }

  /**
   * Converts the type-specific RR to wire format - must be overridden
   *
   * @since 3.1
   */
  protected abstract void rrFromWire(net.posick.DNS.DNSInput in) throws IOException;

  private static Record newRecord(
          net.posick.DNS.Name name, int type, int dclass, long ttl, int length, net.posick.DNS.DNSInput in) throws IOException {
    Record rec;
    rec = getEmptyRecord(name, type, dclass, ttl, in != null);
    if (in != null) {
      if (in.remaining() < length) {
        throw new net.posick.DNS.WireParseException("truncated record");
      }
      in.setActive(length);

      rec.rrFromWire(in);

      if (in.remaining() > 0) {
        throw new WireParseException("invalid record length");
      }
      in.clearActive();
    }
    return rec;
  }

  /**
   * Creates a new record, with the given parameters.
   *
   * @param name The owner name of the record.
   * @param type The record's type.
   * @param dclass The record's class.
   * @param ttl The record's time to live.
   * @param length The length of the record's data.
   * @param data The rdata of the record, in uncompressed DNS wire format. Only the first length
   *     bytes are used.
   */
  public static Record newRecord(
          net.posick.DNS.Name name, int type, int dclass, long ttl, int length, byte[] data) {
    if (!name.isAbsolute()) {
      throw new RelativeNameException(name);
    }
    Type.check(type);
    DClass.check(dclass);
    net.posick.DNS.TTL.check(ttl);

    net.posick.DNS.DNSInput in;
    if (data != null) {
      in = new net.posick.DNS.DNSInput(data);
    } else {
      in = null;
    }
    try {
      return newRecord(name, type, dclass, ttl, length, in);
    } catch (IOException e) {
      return null;
    }
  }

  /**
   * Creates a new record, with the given parameters.
   *
   * @param name The owner name of the record.
   * @param type The record's type.
   * @param dclass The record's class.
   * @param ttl The record's time to live.
   * @param data The complete rdata of the record, in uncompressed DNS wire format.
   */
  public static Record newRecord(net.posick.DNS.Name name, int type, int dclass, long ttl, byte[] data) {
    return newRecord(name, type, dclass, ttl, data.length, data);
  }

  /**
   * Creates a new empty record, with the given parameters.
   *
   * @param name The owner name of the record.
   * @param type The record's type.
   * @param dclass The record's class.
   * @param ttl The record's time to live.
   * @return An object of a subclass of Record
   */
  public static Record newRecord(net.posick.DNS.Name name, int type, int dclass, long ttl) {
    if (!name.isAbsolute()) {
      throw new RelativeNameException(name);
    }
    Type.check(type);
    DClass.check(dclass);
    net.posick.DNS.TTL.check(ttl);

    return getEmptyRecord(name, type, dclass, ttl, false);
  }

  /**
   * Creates a new empty record, with the given parameters. This method is designed to create
   * records that will be added to the QUERY section of a message.
   *
   * @param name The owner name of the record.
   * @param type The record's type.
   * @param dclass The record's class.
   * @return An object of a subclass of Record
   */
  public static Record newRecord(net.posick.DNS.Name name, int type, int dclass) {
    return newRecord(name, type, dclass, 0);
  }

  static Record fromWire(net.posick.DNS.DNSInput in, int section, boolean isUpdate) throws IOException {
    int type;
    int dclass;
    long ttl;
    int length;
    net.posick.DNS.Name name;
    Record rec;

    name = new net.posick.DNS.Name(in);
    type = in.readU16();
    dclass = in.readU16();

    if (section == net.posick.DNS.Section.QUESTION) {
      return newRecord(name, type, dclass);
    }

    ttl = in.readU32();
    length = in.readU16();
    if (length == 0 && isUpdate && (section == net.posick.DNS.Section.PREREQ || section == net.posick.DNS.Section.UPDATE)) {
      return newRecord(name, type, dclass, ttl);
    }
    rec = newRecord(name, type, dclass, ttl, length, in);
    return rec;
  }

  static Record fromWire(net.posick.DNS.DNSInput in, int section) throws IOException {
    return fromWire(in, section, false);
  }

  /** Builds a Record from DNS uncompressed wire format. */
  public static Record fromWire(byte[] b, int section) throws IOException {
    return fromWire(new net.posick.DNS.DNSInput(b), section, false);
  }

  void toWire(net.posick.DNS.DNSOutput out, int section, Compression c) {
    name.toWire(out, c);
    out.writeU16(type);
    out.writeU16(dclass);
    if (section == Section.QUESTION) {
      return;
    }
    out.writeU32(ttl);
    int lengthPosition = out.current();
    out.writeU16(0); /* until we know better */
    rrToWire(out, c, false);
    int rrlength = out.current() - lengthPosition - 2;
    out.writeU16At(rrlength, lengthPosition);
  }

  /** Converts a Record into DNS uncompressed wire format. */
  public byte[] toWire(int section) {
    net.posick.DNS.DNSOutput out = new net.posick.DNS.DNSOutput();
    toWire(out, section, null);
    return out.toByteArray();
  }

  private void toWireCanonical(net.posick.DNS.DNSOutput out, boolean noTTL) {
    name.toWireCanonical(out);
    out.writeU16(type);
    out.writeU16(dclass);
    if (noTTL) {
      out.writeU32(0);
    } else {
      out.writeU32(ttl);
    }
    int lengthPosition = out.current();
    out.writeU16(0); /* until we know better */
    rrToWire(out, null, true);
    int rrlength = out.current() - lengthPosition - 2;
    out.writeU16At(rrlength, lengthPosition);
  }

  /*
   * Converts a Record into canonical DNS uncompressed wire format (all names are
   * converted to lowercase), optionally ignoring the TTL.
   */
  private byte[] toWireCanonical(boolean noTTL) {
    net.posick.DNS.DNSOutput out = new net.posick.DNS.DNSOutput();
    toWireCanonical(out, noTTL);
    return out.toByteArray();
  }

  /**
   * Converts a Record into canonical DNS uncompressed wire format (all names are converted to
   * lowercase).
   */
  public byte[] toWireCanonical() {
    return toWireCanonical(false);
  }

  /**
   * Converts the rdata in a Record into canonical DNS uncompressed wire format (all names are
   * converted to lowercase).
   */
  public byte[] rdataToWireCanonical() {
    net.posick.DNS.DNSOutput out = new net.posick.DNS.DNSOutput();
    rrToWire(out, null, true);
    return out.toByteArray();
  }

  /**
   * Converts the type-specific RR to text format - must be overridden.
   *
   * @since 3.1
   */
  protected abstract String rrToString();

  /** Converts the rdata portion of a Record into a String representation */
  public String rdataToString() {
    return rrToString();
  }

  /** Converts a Record into a String representation */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(name);
    if (sb.length() < 8) {
      sb.append("\t");
    }
    if (sb.length() < 16) {
      sb.append("\t");
    }
    sb.append("\t");
    if (net.posick.DNS.Options.check("BINDTTL")) {
      sb.append(net.posick.DNS.TTL.format(ttl));
    } else {
      sb.append(ttl);
    }
    sb.append("\t");
    if (dclass != DClass.IN || !Options.check("noPrintIN")) {
      sb.append(DClass.string(dclass));
      sb.append("\t");
    }
    sb.append(Type.string(type));
    String rdata = rrToString();
    if (!rdata.equals("")) {
      sb.append("\t");
      sb.append(rdata);
    }
    return sb.toString();
  }

  /**
   * Converts the text format of an RR to the internal format - must be overriden
   *
   * @since 3.1
   */
  protected abstract void rdataFromString(net.posick.DNS.Tokenizer st, net.posick.DNS.Name origin) throws IOException;

  /** Converts a String into a byte array. */
  protected static byte[] byteArrayFromString(String s) throws TextParseException {
    byte[] array = s.getBytes();
    boolean escaped = false;
    boolean hasEscapes = false;

    for (byte item : array) {
      if (item == '\\') {
        hasEscapes = true;
        break;
      }
    }
    if (!hasEscapes) {
      if (array.length > 255) {
        throw new TextParseException("text string too long");
      }
      return array;
    }

    ByteArrayOutputStream os = new ByteArrayOutputStream();

    int digits = 0;
    int intval = 0;
    for (byte value : array) {
      if (escaped) {
        byte b = value;
        if (b >= '0' && b <= '9') {
          digits++;
          intval *= 10;
          intval += b - '0';
          if (intval > 255) {
            throw new TextParseException("bad escape");
          }
          if (digits < 3) {
            continue;
          }
          b = (byte) intval;
        } else if (digits > 0) {
          throw new TextParseException("bad escape");
        }
        os.write(b);
        escaped = false;
      } else if (value == '\\') {
        escaped = true;
        digits = 0;
        intval = 0;
      } else {
        os.write(value);
      }
    }
    if (digits > 0 && digits < 3) {
      throw new TextParseException("bad escape");
    }
    array = os.toByteArray();
    if (array.length > 255) {
      throw new TextParseException("text string too long");
    }

    return os.toByteArray();
  }

  /** Converts a byte array into a String. */
  protected static String byteArrayToString(byte[] array, boolean quote) {
    StringBuilder sb = new StringBuilder();
    if (quote) {
      sb.append('"');
    }
    for (byte value : array) {
      int b = value & 0xFF;
      if (b < 0x20 || b >= 0x7f) {
        sb.append('\\');
        sb.append(byteFormat.format(b));
      } else if (b == '"' || b == '\\') {
        sb.append('\\');
        sb.append((char) b);
      } else {
        sb.append((char) b);
      }
    }
    if (quote) {
      sb.append('"');
    }
    return sb.toString();
  }

  /** Converts a byte array into the unknown RR format. */
  protected static String unknownToString(byte[] data) {
    return "\\# " + data.length + " " + base16.toString(data);
  }

  /**
   * Builds a new Record from its textual representation
   *
   * @param name The owner name of the record.
   * @param type The record's type.
   * @param dclass The record's class.
   * @param ttl The record's time to live.
   * @param st A tokenizer containing the textual representation of the rdata.
   * @param origin The default origin to be appended to relative domain names.
   * @return The new record
   * @throws IOException The text format was invalid.
   */
  public static Record fromString(
          net.posick.DNS.Name name, int type, int dclass, long ttl, net.posick.DNS.Tokenizer st, net.posick.DNS.Name origin) throws IOException {
    Record rec;

    if (!name.isAbsolute()) {
      throw new RelativeNameException(name);
    }
    Type.check(type);
    DClass.check(dclass);
    TTL.check(ttl);

    net.posick.DNS.Tokenizer.Token t = st.get();
    if (t.type == net.posick.DNS.Tokenizer.IDENTIFIER && t.value.equals("\\#")) {
      int length = st.getUInt16();
      byte[] data = st.getHex();
      if (data == null) {
        data = new byte[0];
      }
      if (length != data.length) {
        throw st.exception("invalid unknown RR encoding: length mismatch");
      }
      net.posick.DNS.DNSInput in = new DNSInput(data);
      return newRecord(name, type, dclass, ttl, length, in);
    }
    st.unget();
    rec = getEmptyRecord(name, type, dclass, ttl, true);
    rec.rdataFromString(st, origin);
    t = st.get();
    if (t.type != net.posick.DNS.Tokenizer.EOL && t.type != net.posick.DNS.Tokenizer.EOF) {
      throw st.exception("unexpected tokens at end of record (wanted EOL/EOF, got " + t + ")");
    }
    return rec;
  }

  /**
   * Builds a new Record from its textual representation
   *
   * @param name The owner name of the record.
   * @param type The record's type.
   * @param dclass The record's class.
   * @param ttl The record's time to live.
   * @param s The textual representation of the rdata.
   * @param origin The default origin to be appended to relative domain names.
   * @return The new record
   * @throws IOException The text format was invalid.
   */
  public static Record fromString(net.posick.DNS.Name name, int type, int dclass, long ttl, String s, net.posick.DNS.Name origin)
      throws IOException {
    return fromString(name, type, dclass, ttl, new Tokenizer(s), origin);
  }

  /**
   * Returns the record's name
   *
   * @see net.posick.DNS.Name
   */
  public net.posick.DNS.Name getName() {
    return name;
  }

  /**
   * Returns the record's type
   *
   * @see Type
   */
  public int getType() {
    return type;
  }

  /**
   * Returns the type of RRset that this record would belong to. For all types except SIG/RRSIG,
   * this is equivalent to getType().
   *
   * @return The type of record
   * @see Type
   * @see RRset
   * @see SIGBase#getRRsetType()
   */
  public int getRRsetType() {
    return type;
  }

  /** Returns the record's class */
  public int getDClass() {
    return dclass;
  }

  /** Returns the record's TTL */
  public long getTTL() {
    return ttl;
  }

  /**
   * Converts the type-specific RR to wire format - must be overridden.
   *
   * @since 3.1
   */
  protected abstract void rrToWire(DNSOutput out, Compression c, boolean canonical);

  /**
   * Determines if two Records could be part of the same RRset. This compares the name, type, and
   * class of the Records; the ttl and rdata are not compared.
   */
  public boolean sameRRset(Record rec) {
    return getRRsetType() == rec.getRRsetType() && dclass == rec.dclass && name.equals(rec.name);
  }

  /**
   * Determines if two Records are identical. This compares the name, type, class, and rdata (with
   * names canonicalized). The TTLs are not compared.
   *
   * @param arg The record to compare to
   * @return true if the records are equal, false otherwise.
   */
  @Override
  public boolean equals(Object arg) {
    if (!(arg instanceof Record)) {
      return false;
    }
    Record r = (Record) arg;
    if (type != r.type || dclass != r.dclass || !name.equals(r.name)) {
      return false;
    }
    byte[] array1 = rdataToWireCanonical();
    byte[] array2 = r.rdataToWireCanonical();
    return Arrays.equals(array1, array2);
  }

  /** Generates a hash code based on the Record's data. */
  @Override
  public int hashCode() {
    byte[] array = toWireCanonical(true);
    int code = 0;
    for (byte b : array) {
      code += (code << 3) + (b & 0xFF);
    }
    return code;
  }

  Record cloneRecord() {
    try {
      return (Record) clone();
    } catch (CloneNotSupportedException e) {
      throw new IllegalStateException();
    }
  }

  /**
   * Creates a new record identical to the current record, but with a different name. This is most
   * useful for replacing the name of a wildcard record.
   */
  public Record withName(net.posick.DNS.Name name) {
    if (!name.isAbsolute()) {
      throw new RelativeNameException(name);
    }
    Record rec = cloneRecord();
    rec.name = name;
    return rec;
  }

  /**
   * Creates a new record identical to the current record, but with a different class and ttl. This
   * is most useful for dynamic update.
   */
  Record withDClass(int dclass, long ttl) {
    Record rec = cloneRecord();
    rec.dclass = dclass;
    rec.ttl = ttl;
    return rec;
  }

  /* Sets the TTL to the specified value.  This is intentionally not public. */
  void setTTL(long ttl) {
    this.ttl = ttl;
  }

  /**
   * Compares this Record to another Object.
   *
   * @param arg The Object to be compared.
   * @return The value 0 if the argument is a record equivalent to this record; a value less than 0
   *     if the argument is less than this record in the canonical ordering, and a value greater
   *     than 0 if the argument is greater than this record in the canonical ordering. The canonical
   *     ordering is defined to compare by name, class, type, and rdata.
   * @throws ClassCastException if the argument is not a Record.
   */
  @Override
  public int compareTo(Record arg) {
    if (this == arg) {
      return 0;
    }

    int n = name.compareTo(arg.name);
    if (n != 0) {
      return n;
    }

    n = dclass - arg.dclass;
    if (n != 0) {
      return n;
    }

    n = type - arg.type;
    if (n != 0) {
      return n;
    }

    byte[] rdata1 = rdataToWireCanonical();
    byte[] rdata2 = arg.rdataToWireCanonical();
    int minLen = Math.min(rdata1.length, rdata2.length);
    for (int i = 0; i < minLen; i++) {
      if (rdata1[i] != rdata2[i]) {
        return (rdata1[i] & 0xFF) - (rdata2[i] & 0xFF);
      }
    }

    return rdata1.length - rdata2.length;
  }

  /**
   * Returns the name for which additional data processing should be done for this record. This can
   * be used both for building responses and parsing responses.
   *
   * @return The name to used for additional data processing, or null if this record type does not
   *     require additional data processing.
   */
  public net.posick.DNS.Name getAdditionalName() {
    return null;
  }

  /* Checks that an int contains an unsigned 8 bit value */
  static int checkU8(String field, int val) {
    if (val < 0 || val > 0xFF) {
      throw new IllegalArgumentException(
          "\"" + field + "\" " + val + " must be an unsigned 8 bit value");
    }
    return val;
  }

  /* Checks that an int contains an unsigned 16 bit value */
  static int checkU16(String field, int val) {
    if (val < 0 || val > 0xFFFF) {
      throw new IllegalArgumentException(
          "\"" + field + "\" " + val + " must be an unsigned 16 bit value");
    }
    return val;
  }

  /* Checks that a long contains an unsigned 32 bit value */
  static long checkU32(String field, long val) {
    if (val < 0 || val > 0xFFFFFFFFL) {
      throw new IllegalArgumentException(
          "\"" + field + "\" " + val + " must be an unsigned 32 bit value");
    }
    return val;
  }

  /* Checks that a name is absolute */
  static net.posick.DNS.Name checkName(String field, Name name) {
    if (!name.isAbsolute()) {
      throw new RelativeNameException(
          "'" + name + "' on field " + field + " is not an absolute name");
    }
    return name;
  }

  static byte[] checkByteArrayLength(String field, byte[] array, int maxLength) {
    if (array.length > 0xFFFF) {
      throw new IllegalArgumentException(
          "\"" + field + "\" array must have no more than " + maxLength + " elements");
    }
    byte[] out = new byte[array.length];
    System.arraycopy(array, 0, out, 0, array.length);
    return out;
  }
}
