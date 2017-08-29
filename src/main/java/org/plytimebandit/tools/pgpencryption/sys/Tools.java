package org.plytimebandit.tools.pgpencryption.sys;

public class Tools {

    /**
     * https://gist.github.com/lesleh/7724554
     */
    public static byte[][] chunkArray(byte[] array, int chunkSize) {
        int numOfChunks = (byte) Math.ceil((double) array.length / chunkSize);
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
