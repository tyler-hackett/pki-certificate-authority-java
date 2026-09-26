/*
 * Copyright (C) 2014 Stevens Institute of Technology
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package io.github.tylerhackett.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.util.logging.Logger;

public class FileUtils {
	
	@SuppressWarnings("unused")
	private static final String TAG = FileUtils.class.getCanonicalName();
	
	@SuppressWarnings("unused")
	private static final Logger logger = Logger.getLogger(FileUtils.class.getCanonicalName());
	

	/**
	 * Folder operations
	 */

	public static void ensureFolder(File folder) throws IOException {
		boolean isOk = folder.exists() || folder.mkdirs();
		if (!isOk) {
			throw new FileNotFoundException("Could not create " + folder.getAbsolutePath() + " directory!");
		}
	}

	public static boolean deleteContents(File file, String regex) {
		if (file.isDirectory()) {
			File[] files = file.listFiles();
			if (files != null) {
				for (File child : files) {
					if (child.getAbsoluteFile().getName().matches(regex)) {
						if (!deleteAll(child, regex)) {
							return false;
						}
					}
				}
			}
		}
		return true;
	}

	public static boolean deleteAll(File file, String regex) {
		return deleteContents(file, regex) && file.delete();
	}

	/**
	 * File operations
	 */

	public static Writer openOutputCharFile(File file) throws FileNotFoundException {
		CharsetEncoder encoder = Charset.forName(StringUtils.CHARSET).newEncoder();
		return new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file), encoder));
	}
	
	public static Reader openInputCharFile(File file) throws FileNotFoundException {
		CharsetDecoder decoder = Charset.forName(StringUtils.CHARSET).newDecoder();
		return new BufferedReader(new InputStreamReader(new FileInputStream(file), decoder));
	}

}