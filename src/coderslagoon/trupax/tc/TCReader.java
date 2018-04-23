package coderslagoon.trupax.tc;

import java.io.IOException;



import coderslagoon.baselib.io.BlockDevice;
import coderslagoon.baselib.io.BlockDeviceImpl;
import coderslagoon.tclib.container.Header;
import coderslagoon.tclib.container.Volume;
import coderslagoon.tclib.crypto.BlockCipher;
import coderslagoon.tclib.util.Key;
import coderslagoon.tclib.util.TCLibException;

public class TCReader extends BlockDeviceImpl {
    final BlockDevice bdev;
    final Volume      vol;
    final long        num0;
    final long        size;

    protected Header header;

    public TCReader(BlockDevice bdev, Key key, 
                    boolean tryBackupHeader, boolean veraCrypt)
        throws IOException, TCLibException {
        
        super(true, false, false, -1L, bdev.blockSize());
        this.bdev = bdev;
        try {
            this.header = openHeader(0, key, veraCrypt);
        }
        catch (TCLibException tle) {
            if (tryBackupHeader)
                this.header = openHeader
                        (bdev.size() - Header.BLOCK_COUNT, key, veraCrypt);
            else
                throw tle;
        }
        finally {
            key.erase();
        }
        if (0 != this.header.dataAreaSize   % this.bdev.blockSize() ||
            0 != this.header.dataAreaOffset % this.bdev.blockSize()) {
            throw new TCLibException();
        }
        this.size = this.header.dataAreaSize   / this.bdev.blockSize();
        this.num0 = this.header.dataAreaOffset / this.bdev.blockSize();
        this.vol = new Volume(BlockCipher.Mode.DECRYPT, this.header);
    }

    private Header openHeader(long num, Key key, boolean veraCrypt)
            throws IOException, TCLibException {
        final byte[] data = new byte[Header.SIZE];
        for (int ofs = 0; ofs < data.length; ofs += Header.BLOCK_SIZE) {
            this.bdev.read(num++, data, ofs);
        }
        return new Header(key, data, 0, veraCrypt);
    }

    protected void internalRead(long num, byte[] block, int ofs) throws IOException {
        num += this.num0;
        this.bdev.read(num, block, ofs);
        try {
            this.vol.processBlock(num, block, ofs);
        }
        catch (TCLibException tle) {
            throw new IOException(tle);
        }
    }

    protected void internalWrite(long num, byte[] block, int ofs) throws IOException {
        throw new IOException();
    }

    public void close(boolean err) throws IOException {
        this.header.erase();
        this.vol   .erase();

        this.bdev.close(err);
    }

    public long size() {
        return this.size;
    }

    public String nameOfHashFunction() {
        try {
            return this.header.hashFunction.getDeclaredConstructor(new Class[0]).newInstance().name();
        }
        catch (Exception e) {
            return e.getLocalizedMessage();
        }
    }

    public String nameOfBlockCipher() {
        try {
            return this.header.blockCipher.getDeclaredConstructor(new Class[0]).newInstance().name();
        }
        catch (Exception e) {
            return e.getLocalizedMessage();
        }
    }
}
