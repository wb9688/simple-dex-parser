package wb9688.simple_dex_parser;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import wb9688.simple_dex_parser.exceptions.InvalidDexMagicException;
import wb9688.simple_dex_parser.exceptions.UnsupportedDexVersionException;

public class SimpleDexParser {
    private final InputStream input;
    private long bytesRead = 0;
    private long[] stringOffs;
    private long[] typeOffs;
    private String[] types;
    private String version;

    public SimpleDexParser(final InputStream input)
            throws IOException, InvalidDexMagicException, UnsupportedDexVersionException {
        this.input = input;
        if (!checkDexFileMagic()) {
            throw new InvalidDexMagicException();
        }

        // TODO: Check checksum and signature
        skipBytes(48);

        final int stringIdsSize = (int) getUint(readBytes(4));
        final long stringIdsOff = getUint(readBytes(4));

        final int typeIdsSize = (int) getUint(readBytes(4));
        final long typeIdsOff = getUint(readBytes(4));

        this.stringOffs = parseIds(stringIdsSize, stringIdsOff);
        this.typeOffs = parseIds(typeIdsSize, typeIdsOff);

        parseTypes();
    }

    private boolean checkDexFileMagic() throws IOException, UnsupportedDexVersionException {
        final byte[] magic = readBytes(8);
        final byte[] correct_magic = new byte[]{0x64, 0x65, 0x78, 0x0A};
        for (int i = 0; i < 4; i++) {
            if (magic[i] != correct_magic[i]) {
                return false;
            }
        }

        final StringBuilder versionBuilder = new StringBuilder(3);
        for (int i = 4; i < 7; i++) {
            versionBuilder.append((char) magic[i]);
        }
        this.version = versionBuilder.toString();

        if (!this.version.equals("035") && !this.version.equals("037")
                && !this.version.equals("038") && !this.version.equals("039")
                && !this.version.equals("040")) {
            throw new UnsupportedDexVersionException();
        }

        return magic[7] == 0x00;
    }

    private byte[] readBytes(final int amount) throws IOException {
        final byte[] bytes = new byte[amount];
        int read = 0;
        int tmpRead;
        while (read != amount) {
            tmpRead = this.input.read(bytes, read, amount - read);
            if (tmpRead == -1) {
                throw new IOException();
            }
            read += tmpRead;
        }
        this.bytesRead += amount;
        return bytes;
    }

    private byte readByte() throws IOException {
        final int tmpByte = this.input.read();
        if (tmpByte == -1) {
            throw new IOException();
        }
        this.bytesRead++;
        return (byte) tmpByte;
    }

    private void skipBytes(final long amount) throws IOException {
        long skipped = 0;
        while (skipped != amount) {
            skipped += this.input.skip(amount - skipped);
        }
        this.bytesRead += amount;
    }

    private long getUint(final byte[] bytes) {
        if (bytes.length != 4) {
            throw new IllegalArgumentException();
        }
        final long a = bytes[0] & 0xFF;
        final long b = (bytes[1] & 0xFF) << 8;
        final long c = (bytes[2] & 0xFF) << 16;
        final long d = (bytes[3] & 0xFF) << 24;
        return a + b + c + d;
    }

    private long getUleb128() throws IOException {
        long result = 0;
        int num = 0;
        boolean end = false;
        while (!end) {
            final byte readByte = readByte();
            if ((readByte & (1 << 7)) == 0) {
                end = true;
            }
            for (int i = 0; i < 7; i++) {
                if ((readByte & (1 << i)) != 0) {
                    result += (6 * num) + (1 << i);
                }
            }
            num++;
        }

        return result;
    }

    private long[] parseIds(final int stringIdsSize, final long stringIdsOff)
            throws IOException {
        skipBytes(stringIdsOff - this.bytesRead);
        final long[] dataOffs = new long[stringIdsSize];
        for (int i = 0; i < stringIdsSize; i++) {
            dataOffs[i] = getUint(readBytes(4));
        }
        return dataOffs;
    }

    private void parseTypes() throws IOException {
        final long[] actualTypeOffs = new long[this.typeOffs.length];
        for (int i = 0; i < this.typeOffs.length; i++) {
            actualTypeOffs[i] = this.stringOffs[(int) this.typeOffs[i]];
        }

        this.types = new String[this.typeOffs.length];
        for (int i = 0; i < actualTypeOffs.length; i++) {
            skipBytes(actualTypeOffs[i] - this.bytesRead);

            final long utflen = getUleb128();

            final List<Byte> bytes = new ArrayList<>();
            bytes.add((byte) (utflen >>> 8));
            bytes.add((byte) utflen);

            byte currentByte;
            do {
                bytes.add(currentByte = readByte());
            } while (currentByte != 0x00);

            final DataInputStream bytesStreamWrapper = new DataInputStream(new InputStream() {
                private int index = 0;

                @Override
                public int read() {
                    try {
                        return bytes.get(this.index++);
                    } catch (IndexOutOfBoundsException e) {
                        return -1;
                    }
                }
            });

            this.types[i] = bytesStreamWrapper.readUTF();
        }
    }

    public String getVersion() {
        return this.version;
    }

    public String[] getTypes() {
        return this.types;
    }
}
