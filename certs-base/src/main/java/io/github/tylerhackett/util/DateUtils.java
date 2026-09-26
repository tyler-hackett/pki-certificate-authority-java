package io.github.tylerhackett.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Logger;

public class DateUtils {
	
	private static final String TAG = DateUtils.class.getCanonicalName();
	private static final Logger logger = Logger.getLogger(TAG);
	
	public static final long ONE_HOUR = 60 * 60 * 1000;
	public static final long ONE_DAY = 24 * ONE_HOUR;
	
	private DateUtils() {}

	public static DateFormat getDateTimeFormat() {
		return SimpleDateFormat.getDateTimeInstance();
	}

	public static String dateTimeFormat(Date date) {
		if (date == null) {
			date = now();
		}
		return getDateTimeFormat().format(date);
	}

	public static Date now() {
		return new Date(System.currentTimeMillis());
	}

	public static Date then(long msecsInFuture) {
		return new Date(System.currentTimeMillis() + msecsInFuture);
	}

	public static boolean expired(Date when, long msecsDuration) {
		return when.getTime()+msecsDuration < System.currentTimeMillis();
	}

}
