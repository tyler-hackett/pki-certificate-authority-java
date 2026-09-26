package io.github.tylerhackett.util;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.logging.Logger;


public class StringUtils {
	
	@SuppressWarnings("unused")
	private static final Logger logger = Logger.getLogger(StringUtils.class.getCanonicalName());
	
	/*
	 * Byte arrays and character set encoding
	 */
	
	public static final String CHARSET = "UTF-8";
	
	public static String toString(byte[] b) {
		return toString(b, b.length);
	}
	
	public static String toString(byte[] b, int len) {
		try {
			return new String(b, 0, len, CHARSET);
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Unsupported UTF-8 encoding!");
			// return null;
		}
	}

	private enum TitleCaseState {
		NORMAL, SEPARATOR, TITLE
	}

	@SuppressWarnings("unused")
	private static StringBuilder makeTitleCase(String s) {
		StringBuilder sb = new StringBuilder();
		TitleCaseState state = TitleCaseState.SEPARATOR;
		for (int i=0; i<s.length(); i++) {
			char ch = s.charAt(i);
			switch (state) {
			case NORMAL:
				if (ch=='_') {
					state = TitleCaseState.SEPARATOR;
				} else if (Character.isUpperCase(ch)) {
					sb.append(ch);
					state = TitleCaseState.TITLE;
				} else {
					sb.append(ch);
				}
				break;
			case SEPARATOR:
				if (ch=='_') {
					/* Keep going */
				} else if (Character.isUpperCase(ch)) {
					sb.append(ch);
					state = TitleCaseState.TITLE;
				} else {
					sb.append(Character.toUpperCase(ch));
					state = TitleCaseState.NORMAL;
				}
				break;
			case TITLE:
				if (ch=='_') {
					state = TitleCaseState.SEPARATOR;
				} else if (Character.isUpperCase(ch)) {
					sb.append(Character.toLowerCase(ch));
				} else {
					sb.append(ch);
					state = TitleCaseState.NORMAL;
				}
				break;
			}
		}
		return sb;
	}
	
	public static <T> String toString(Collection<T> set) {
		StringBuffer sb = new StringBuffer("[");
		int j=0;
		for (T s : set) {
			if (j > 0) {
				sb.append(',');
			}
			sb.append(s==null ? "null" : s.toString());
			j++;
		}
		sb.append(']');
		return new String(sb);
	}
	
	public static String toString(char[] b) {
		return toString(b, b.length);
	}
	
	public static String toString(char[] b, int len) {
		return new String(b, 0, len);
	}

	/*
	 * Blobs
	 */
	
	public static byte[] readBlob(DataInputStream in) throws IOException {
		byte[] b = new byte[in.readInt()];
		in.readFully(b, 0, b.length);
		return b;
	}
	
	public static void writeBlob(DataOutputStream out, byte[] b) throws IOException {
		out.writeInt(b.length);
		out.write(b);
	}

}
