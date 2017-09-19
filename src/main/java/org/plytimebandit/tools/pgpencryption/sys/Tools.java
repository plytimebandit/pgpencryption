package org.plytimebandit.tools.pgpencryption.sys;

import java.math.BigDecimal;

public class Tools {

    /**
     * https://gist.github.com/lesleh/7724554
     */
    public static byte[][] chunkArray(byte[] array, int chunkSize) {
        BigDecimal bigDecimal = new BigDecimal(Math.ceil((double) array.length / chunkSize));
        int numOfChunks = bigDecimal.toBigInteger().intValue();
        byte[][] output = new byte[numOfChunks][];

        for (int i = 0; i < numOfChunks; ++i) {
            int start = i * chunkSize;
            int length = Math.min(array.length - start, chunkSize);

            byte[] temp = new byte[length];
            System.arraycopy(array, start, temp, 0, length);
            output[i] = temp;
        }

        return output;
    }

}
