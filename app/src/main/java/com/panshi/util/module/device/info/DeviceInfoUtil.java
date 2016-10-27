package com.panshi.util.module.device.info;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.app.ActivityManager.RunningAppProcessInfo;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.TrafficStats;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.os.StatFs;
import android.os.SystemClock;
import android.provider.Settings;
import android.provider.Settings.Secure;
import android.telephony.NeighboringCellInfo;
import android.telephony.TelephonyManager;
import android.telephony.cdma.CdmaCellLocation;
import android.telephony.gsm.GsmCellLocation;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.WindowManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 获得设备信息工具类
 */
@SuppressLint("NewApi")
public class DeviceInfoUtil {

	private final static String SHA1_ALGORITHM = "SHA-1";
	private final static String CHAR_SET = "iso-8859-1";

	/**
	 * @todo：获取设备的品牌名：例如xiaomi，samsung
	 * @return brandName
	 */
	public static String getFactoryBrandName() {
		try {
			return Build.BRAND;
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 获得系统版本
	 */
	public static String getOSVersion() {
		try {
			return Build.VERSION.RELEASE;
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 设备的名称
	 */
	public static String getDevice() {
		try {
			return Build.MODEL;
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 获得手机的：宽＊density + x + 高＊density
	 */

	public static String getResolution(Context context) {
		try {
			WindowManager wm = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
			DisplayMetrics metrics = new DisplayMetrics();
			wm.getDefaultDisplay().getMetrics(metrics);
			return metrics.widthPixels + "x" + metrics.heightPixels;
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 获得注册运营商的名字
	 */
	public static String getCarrier(Context context) {
		try {
			TelephonyManager manager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
			return manager.getNetworkOperatorName();
		} catch (Exception e) {
			e.printStackTrace();
			return "";
		}
	}

	/**
	 * 获得设备IMEI标识
	 */
	public static String getImei(Context mContext) {
		try {
			if (selfPermissionGranted(mContext, Manifest.permission.READ_PHONE_STATE)) {
				TelephonyManager manager = (TelephonyManager) mContext.getSystemService(Context.TELEPHONY_SERVICE);
				return manager.getDeviceId();
			} else {
				return "";
			}
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 获得本地语言和国家
	 * 
	 * @return
	 */
	public static String getLocale() {
		try {
			Locale locale = Locale.getDefault();
			return locale.getLanguage() + "_" + locale.getCountry();
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 获得当前应用的版本号
	 * 
	 * @param context
	 * @return
	 */
	public static String appVersion(Context context) {
		String result = "";
		try {
			result = context.getPackageManager().getPackageInfo(context.getPackageName(), 0).versionName;
		} catch (NameNotFoundException e) {
			result = "";
		}

		return result;
	}

	/**
	 * 获得设备的IP地址
	 * 
	 * @param context
	 * @return
	 */

	public static String getIP(Context context) {
		String ip = "";
		StringBuilder IPStringBuilder = new StringBuilder();
		try {
			for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
				NetworkInterface intf = en.nextElement();
				for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {
					InetAddress inetAddress = enumIpAddr.nextElement();
					if (!inetAddress.isLoopbackAddress() && !inetAddress.isLinkLocalAddress()
							&& inetAddress.isSiteLocalAddress()) {
						IPStringBuilder.append(inetAddress.getHostAddress().toString() + "\n");
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (!TextUtils.isEmpty(IPStringBuilder)) {
			ip = IPStringBuilder.toString();
		} else {
			ip = "";
		}
		return ip;
	}

	/**
	 * 获取Ip
	 * @param ctx
	 * @return
     */
	public static String getCommonIp(Context ctx) {
		try {
			WifiManager wifiManager = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
			if (wifiManager != null && !wifiManager.isWifiEnabled()) {
				return getIP(ctx);
			} else {
				return getIP2(ctx);
			}
		} catch (Exception e) {
			return "";
		}
	}

	public static String getIP2(Context ctx) {
		try {
			// 获取wifi服务
			WifiManager wifiManager = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
			// 判断wifi是否开启
			WifiInfo wifiInfo = wifiManager.getConnectionInfo();
			int ipAddress = wifiInfo.getIpAddress();
			String ip = intToIp(ipAddress);
			return ip;
		} catch (Exception e) {
			return "";
		}
	}

	private static String intToIp(int i) {
		return (i & 0xFF) + "." + ((i >> 8) & 0xFF) + "." + ((i >> 16) & 0xFF) + "." + (i >> 24 & 0xFF);
	}

	/**
	 * 获得设备device 、id 、display、product等
	 * 
	 * @return
	 */
	public static String getModel() {
		String device = Build.DEVICE;
		String id = Build.ID;
		String display = Build.DISPLAY;
		String product = Build.PRODUCT;
		String board = Build.BOARD;
		String brand = Build.BRAND;
		String model = Build.MODEL;
		return device + "," + id + "," + display + "," + product + "," + board + "," + brand + "," + model;
	}

	/**
	 * 判断当前网络是否可用
	 * 
	 * @param context
	 * @return
	 */
	public static boolean isNetworkAvailable(Context context) {
		try {
			if (context != null) {
				ConnectivityManager connectivity = (ConnectivityManager) context
						.getSystemService(Context.CONNECTIVITY_SERVICE);
				if (connectivity == null) {
					return false;
				} else {
					NetworkInfo[] info = connectivity.getAllNetworkInfo();
					if (info != null) {
						for (int i = 0; i < info.length; i++) {
							if (info[i].getState() == NetworkInfo.State.CONNECTED) {
								return true;
							}
						}
					}
				}
			} else {
				return false;
			}
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return false;
	}

	/**
	 * 获取当前应用的名
	 * 
	 * @param context
	 * @return
	 */
	public static String getAppName(Context context) {
		try {
			PackageInfo pkg = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
			String appName = pkg.applicationInfo.loadLabel(context.getPackageManager()).toString();
			return appName;
		} catch (NameNotFoundException e) {
			e.printStackTrace();
		}
		return "";
	}

	/**
	 * @todo：获取当前应用程序PACKAGE NAME
	 * @return APP PACKAGE NAME
	 */
	public static String getAppPackageName(Context context) {
		try {
			PackageManager manager = context.getPackageManager();
			PackageInfo info = manager.getPackageInfo(context.getPackageName(), 0);
			if (info != null && !TextUtils.isEmpty(info.versionName)) {
				return info.packageName;
			}
			return "";
		} catch (Exception e) {
			return "";
		}
	}
	/**
	 * @todo：获取当前应用程序PACKAGE VERSION
	 * @return APP PACKAGE Version
	 */
	public static String getAppVersion(Context context) {
		try {
			PackageManager manager = context.getPackageManager();
			PackageInfo info = manager.getPackageInfo(context.getPackageName(), 0);
			if (info != null && !TextUtils.isEmpty(info.versionName)) {
				return info.versionName;
			}
			return "";
		} catch (Exception e) {
			e.printStackTrace();
			return "";
		}
	}

	/**
	 * 获取系统时区
	 */
	public static String getTimeZone() {
		try {
			TimeZone tz = TimeZone.getDefault();
			String s = tz.getDisplayName(false, TimeZone.SHORT) + "+" + tz.getID();
			return s;
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 获得设备mac
	 */
	public static String getMacAddress(Context context) {
		String result = "";
		try {
			WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
			if (wifiManager != null) {
				WifiInfo wifiInfo = wifiManager.getConnectionInfo();
				if (wifiInfo != null) {
					result = wifiInfo.getMacAddress();
				}
			}
		} catch (Exception e) {
			result = "";
		}
		return result;
	}

	/**
	 * 获取apmac
	 */
	public static String getApMac(Context context) {
		String apmac = "";
		try {
			WifiManager wfm = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
			WifiInfo wfi = wfm.getConnectionInfo();

			if (null != wfi && !TextUtils.isEmpty(wfi.getBSSID())) {
				apmac = wfi.getBSSID();
			}
		} catch (Exception e) {
			apmac = "";
		}
		if (!TextUtils.isEmpty(apmac)) {
			apmac = apmac.replaceAll(":", "");
		}
		return apmac;
	}

	/**
	 * 获得设备ONIN,这里使用AndroidID
	 */
	public static String getODIN1(Context context) {
		String androidId = "";
		try {
			androidId = Settings.System.getString(context.getContentResolver(), Secure.ANDROID_ID);
			return SHA1(androidId);
		} catch (Exception e) {
			return androidId;
		}
	}

	private static String convertToHex(byte[] data) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do {
				if ((0 <= halfbyte) && (halfbyte <= 9))
					buf.append((char) ('0' + halfbyte));
				else
					buf.append((char) ('a' + (halfbyte - 10)));
				halfbyte = data[i] & 0x0F;
			} while (two_halfs++ < 1);
		}
		return buf.toString();
	}

	/**
	 * 对字符串进行加密处理
	 */
	private static String SHA1(String text) {
		try {
			MessageDigest md;
			md = MessageDigest.getInstance(SHA1_ALGORITHM);
			byte[] sha1hash;
			md.update(text.getBytes(CHAR_SET), 0, text.length());
			sha1hash = md.digest();
			return convertToHex(sha1hash);
		} catch (Exception e) {
			return null;
		}
	}

	private static boolean selfPermissionGranted(Context ctx, String permission) {
		boolean result = true;
		int targetSdkVersion = Build.VERSION.SDK_INT;
		try {
			if (targetSdkVersion >= 23) {
				if(Reflection.getContextCompat(ctx)){
					int verValue=Reflection.getContextCompatValue(ctx, permission);
					result=verValue== PackageManager.PERMISSION_GRANTED;
//					result = ContextCompat.checkSelfPermission(ctx, permission) == PackageManager.PERMISSION_GRANTED;
				}else{
					return true;
				}
			} else {
				// result = PermissionChecker.checkSelfPermission(ctx,
				// permission) == PermissionChecker.PERMISSION_GRANTED;
				return true;
			}
		} catch (Exception e) {
			return true;
		}
		return result;
	}

	private static int getSdkVersion(Context context) {
		int targetSdkVersion = 0;
		try {
			PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
			targetSdkVersion = info.applicationInfo.targetSdkVersion;
		} catch (NameNotFoundException e) {
			e.printStackTrace();
			targetSdkVersion = 0;
		}
		return targetSdkVersion;
	}

	/**
	 * 获取mcc
	 */
	public static String getMcc(Context context) {
		try {
			String msetmSimCardMCC = getSimCardOperatorCode(context);
			if (!TextUtils.isEmpty(msetmSimCardMCC)) {
				msetmSimCardMCC = msetmSimCardMCC.substring(0, 3);
			}
			return msetmSimCardMCC;
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 获取mnc
	 */
	public static String getMnc(Context context) {
		try {
			String msetmSimCardMNC = getSimCardOperatorCode(context);
			if (!TextUtils.isEmpty(msetmSimCardMNC)) {
				msetmSimCardMNC = msetmSimCardMNC.substring(3);
			}
			return msetmSimCardMNC;
		} catch (Exception e) {
			return "";
		}
	}
	/**
	 * 获取imsi
	 * 
	 * @param context
	 */
	public static String getImsi(Context context) {
		try {
			if (null != context) {
				if (selfPermissionGranted(context, Manifest.permission.READ_PHONE_STATE)) {
					TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
					String imsi = tm.getSubscriberId();
					if (!TextUtils.isEmpty(imsi)) {
						return imsi;
					}
				} else {
					return "";
				}
			}
			return "";
		} catch (Exception e) {
			e.printStackTrace();
			return "";
		}
	}

	public static String getSimCardOperatorCode(Context context) {
		try {
			String operator = "";
			String UNKNOWN = "";
			try {
				TelephonyManager telephonyManager = null;
				telephonyManager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
				if (null != telephonyManager) {
					operator = telephonyManager.getNetworkOperator();
					if (operator == null) {
						operator = UNKNOWN;
					}
				}
			} catch (Exception e) {
				return UNKNOWN;
			}
			return operator;
		} catch (Exception e) {
			e.printStackTrace();
			return "";
		}
	}

	/**
	 * 是否root
	 * 
	 * @return
	 */
	public static String isRootSystem() {
		File f = null;
		boolean flag=false;
		final String kSuSearchPaths[] = { "/system/bin/", "/system/xbin/", "/system/sbin/", "/sbin/", "/vendor/bin/" };
		try {
			for (int i = 0; i < kSuSearchPaths.length; i++) {
				f = new File(kSuSearchPaths[i] + "su");
				if (f != null && f.exists() && isExecutable(kSuSearchPaths[i] + "su")) {
					flag=true;
				}
			}
		} catch (Exception e) {
			flag=false;
		}
		return flag?"1":"0";
	}

	public static boolean isDeviceRooted() {
		if (checkRootMethod1()) {
			return true;
		}
		if (checkRootMethod2()) {
			return true;
		}
		if (checkRootMethod3()) {
			return true;
		}
		return false;
	}

	public static boolean isRoot() {
		String binPath = "/system/bin/su";
		String xBinPath = "/system/xbin/su";
		if (new File(binPath).exists() && isExecutable(binPath))
			return true;
		if (new File(xBinPath).exists() && isExecutable(xBinPath))
			return true;
		return false;
	}

	private static boolean isExecutable(String filePath) {
		Process p = null;
		try {
			p = Runtime.getRuntime().exec("ls -l " + filePath);
			// 获取返回内容

			BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String str = in.readLine();
			if (str != null && str.length() >= 4) {
				char flag = str.charAt(3);
				if (flag == 's' || flag == 'x')
					return true;
			}
		} catch (IOException e) {
			//e.printStackTrace();
		} finally {
//			if (p != null) {
//				try {
//					p.destroy();
//				} catch (Exception e) {
//				}
//			}
			try {
				if (p != null) {
					// use exitValue() to determine if process is still running.
					p.exitValue();
				}
			} catch (IllegalThreadStateException e) {
				// process is still running, kill it.
				p.destroy();
			}
		}
		return false;
	}

	/**
	 * apname-wifiname
	 */
	public static String getApName(Context ctx) {
		String wifiname = "";
		try {
			WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);

			WifiInfo wifiInfo = wm.getConnectionInfo();
			if (wifiInfo != null) {
				wifiname = wifiInfo.getSSID() == null ? "" : wifiInfo.getSSID().replace("\"", "");
			}
		} catch (Exception e) {
			wifiname = "";
		}

		return wifiname;
	}

	public static boolean checkRootMethod1() {
		try {
			String buildTags = Build.TAGS;
			if (buildTags != null && buildTags.contains("test-keys")) {
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	public static boolean checkRootMethod2() {
		try {
			File file = new File("/system/app/Superuser.apk");
			if (file.exists()) {
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	public static boolean checkRootMethod3() {
		File f = null;
		String kSuSearchPaths[] = { "/system/bin/", "/system/xbin/", "/system/sbin/", "/sbin/", "/vendor/bin/" };
		try {
			for (int i = 0; i < kSuSearchPaths.length; i++) {
				f = new File(kSuSearchPaths[i] + "su");
				if (f != null && f.exists()) {
					return true;
				}
			}
		} catch (Exception e) {
			return false;
		}
		return false;
	}

	public static boolean isBackground(Context context) {
		try {
			ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
			List<RunningAppProcessInfo> appProcesses = activityManager.getRunningAppProcesses();
			if (appProcesses != null) {
				for (RunningAppProcessInfo appProcess : appProcesses) {
					if (appProcess.processName.equals(context.getPackageName())) {
						if (appProcess.importance != RunningAppProcessInfo.IMPORTANCE_FOREGROUND) {
							return true;
						} else {
							return false;
						}
					}
				}
			}
		} catch (Exception e) {
			return false;
		}
		return false;
	}

	@SuppressLint("NewApi")
	public static boolean isScreenOn(Context ctx) {
		if (ctx == null)
			return false;
		boolean flag = false;
		try {
			PowerManager localPowerManager = (PowerManager) ctx.getSystemService("power");
			flag = localPowerManager.isScreenOn();
		} catch (Exception localException) {
			flag = false;
		}
		return flag;
	}

	public static String getGoogleAdvertisingId(Context ctx) {
		String playAdId = null;
		try {
			boolean isGooglePlayServicesAvailable = Reflection.isGooglePlayServicesAvailable(ctx);
			if (isGooglePlayServicesAvailable) {
				playAdId = Reflection.getPlayAdId(ctx);
				if (playAdId == null) {
					playAdId = "";
					//Log.w("JiceSDK", "Unable to get google play services AdvertisingID.");
				}
			} else {
				//Log.w("JiceSDK", "google play service is unavailable.");
				playAdId = "";
			}
		} catch (Exception e) {
			playAdId = "";
		}
		return playAdId;
	}

	/**
	 * 收集屏幕分辨率
	 * 
	 * @return
	 */
	public static String getScreenPixels(Context mContext) {
		String wh = "";
		try {
			WindowManager wm = (WindowManager) mContext.getSystemService(Context.WINDOW_SERVICE);
			Display display = wm.getDefaultDisplay();
			DisplayMetrics dm = new DisplayMetrics();
			display.getMetrics(dm);
			int screenW = dm.widthPixels;
			int screenH = dm.heightPixels;
			wh = screenW + "x" + screenH;
		} catch (Exception e) {
			e.printStackTrace();
			wh = "";
		}
		return wh;
	}

	public static String getCurrentNetType(Context context) {
		String type = "";
		try {
			ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
			NetworkInfo info = cm.getActiveNetworkInfo();
			if (info == null || !info.isAvailable()) {
				type = "";
			} else if (info.getType() == ConnectivityManager.TYPE_WIFI) {
				type = "wifi";
			} else if (info.getType() == ConnectivityManager.TYPE_MOBILE) {
				int subType = info.getSubtype();
				if (subType == TelephonyManager.NETWORK_TYPE_CDMA || subType == TelephonyManager.NETWORK_TYPE_GPRS
						|| subType == TelephonyManager.NETWORK_TYPE_EDGE) {
					type = "2g";
				} else if (subType == TelephonyManager.NETWORK_TYPE_UMTS
						|| subType == TelephonyManager.NETWORK_TYPE_HSDPA
						|| subType == TelephonyManager.NETWORK_TYPE_EVDO_A
						|| subType == TelephonyManager.NETWORK_TYPE_EVDO_0
						|| subType == TelephonyManager.NETWORK_TYPE_EVDO_B
						|| subType == TelephonyManager.NETWORK_TYPE_HSPA
						|| subType == TelephonyManager.NETWORK_TYPE_HSUPA
						|| subType == TelephonyManager.NETWORK_TYPE_EHRPD
						|| subType == TelephonyManager.NETWORK_TYPE_HSPAP) {
					type = "3g";
				} else if (subType == TelephonyManager.NETWORK_TYPE_LTE) {// LTE是3g到4g的过渡，是3.9G的全球标准
					type = "4g";
				}
			}
		} catch (Exception e) {
			type = "";
		}
		return type;
	}

	/**
	 * Return WIFI BSSID---路由 mac
	 */
	public static String getBSSID(Context context) {
		try {
			WifiManager wfm = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
			WifiInfo wfi = wfm.getConnectionInfo();

			if (null != wfi && !TextUtils.isEmpty(wfi.getBSSID())) {
				return wfi.getBSSID();
			} else {
				return "";
			}
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * 获取apmac
	 */
	public static String getApMacName(Context context) {
		String apmac = "";
		try {
			WifiManager wfm = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
			WifiInfo wfi = wfm.getConnectionInfo();

			if (null != wfi && !TextUtils.isEmpty(wfi.getSSID())) {
				apmac = wfi.getSSID();
			}
		} catch (Exception e) {
			apmac = "";
		}
		if (!TextUtils.isEmpty(apmac)) {
			apmac = apmac.replaceAll(":", "");
		}
		return apmac;
	}

	/**
	 * Return SSID
	 */
	public static String getSSID(Context context) {
		try {
			WifiManager wfm = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
			WifiInfo wfi = wfm.getConnectionInfo();
			String mSSID = "";
			if (null != wfi && !TextUtils.isEmpty(wfi.getSSID())) {
				// 只允许字母和数字 String regEx = "[^a-zA-Z0-9]";
				mSSID = wfi.getSSID();
				String regEx = "[`~!@#$%^&*()+=|{}':;',//[//].<>/?~！@#￥%……&*（）——+|{}【】‘；：”“’。，、？]";
				Pattern pattern = Pattern.compile(regEx);
				Matcher matcher = pattern.matcher(mSSID);
				mSSID = matcher.replaceAll("").trim();
				mSSID = mSSID.replaceAll("\"", "").replaceAll("\\s+", "").trim();
				return mSSID;
			} else {
				return "";
			}
		} catch (Exception e) {
			return "";
		}

	}

	public static String getBootTime() {
		try {
			return SystemClock.elapsedRealtime() + "";
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * SD卡剩余空间 PS:默认是手机内置存储剩余容量，如果设备[默认存储位置]更改为外置SD卡，则该方法获取的是外置SD卡可用容量
	 */
	public static long getSDFreeSize() {
		try {
			File path = Environment.getExternalStorageDirectory();
			StatFs statfs = new StatFs(path.getPath());
			// 获得单个数据块的大小
			long blocksize = statfs.getBlockSize();
			// 获得空闲数据块的个数
			long freeblock = statfs.getAvailableBlocks();
			// return (freeblock * blocksize) / 1024 / 1024; // 单位MB
			return (freeblock * blocksize);
		} catch (Exception e) {
			return 0;
		}

	}

	/**
	 * SD卡总容量 PS:默认是手机内置存储容量，如果设备[默认存储位置]更改为外置SD卡，则该方法获取的是外置SD卡容量
	 * 
	 **/
	public static long getSDAllsize() {
		try {
			File path = Environment.getExternalStorageDirectory();
			StatFs statfs = new StatFs(path.getPath());
			// 获得单个数据块的大小
			long blocksize = statfs.getBlockSize();
			// 获得全部数据块的个数
			long allBlock = statfs.getBlockCount();
			// return (allBlock * blocksize) / 1024 / 1024; // 单位MB
			return allBlock * blocksize;
		} catch (Exception e) {
			e.printStackTrace();
			return 0;
		}
	}

	/**
	 * 获取ram总大小
	 * 
	 * @return
	 */
	@SuppressLint("NewApi")
	public static long getRAMAll(Context ctx) {
		try {
			ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
			ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
			am.getMemoryInfo(mi);
			return mi.totalMem;
		} catch (Exception e) {
			return 0;
		}
	}

	/**
	 * 获取ram可用大小
	 * 
	 * @return
	 */
	public static long getRAMFree(Context ctx) {
		try {
			ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
			ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
			am.getMemoryInfo(mi);
			return mi.availMem;
		} catch (Exception e) {
			return 0;
		}
	}

	/**
	 * arraylist转为数组
	 * 
	 * @param list
	 * @return
	 */
	public static String getAppList(Context ctx) {
		JSONArray applist = new JSONArray();
		try {
			List<PackageInfo> packages = ctx.getPackageManager().getInstalledPackages(0);
			if (packages != null) {
				for (PackageInfo packageInfo : packages) {
					boolean isPreinstalled = false;
					if ((packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) > 0) {
						isPreinstalled = true;
					} else {
						isPreinstalled = false;
					}
					JSONObject appItem = new JSONObject();

					String appname = packageInfo.applicationInfo == null ? ""
							: packageInfo.applicationInfo.loadLabel(ctx.getPackageManager()).toString();
					String packagename = packageInfo.packageName == null ? "" : packageInfo.packageName;
					appItem.put("appName", appname);
					appItem.put("packageName", packagename);
					appItem.put("firstime", packageInfo.firstInstallTime + "");
					appItem.put("isPreInstalled", isPreinstalled + "");
					applist.put(appItem);
				}
			}
		} catch (Exception e) {
			return "";
		}
		if (!TextUtils.isEmpty(applist.toString())) {
			return applist.toString();
		}
		return "";
	}

	public static String getWirelessList(Context ctx) {
		JSONArray aplist = new JSONArray();
		try {
			WifiManager wm = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);
			List<WifiConfiguration> wificonfiglist = wm.getConfiguredNetworks();
			WifiInfo wifiInfo = wm.getConnectionInfo();
			String cssid = "";
			int cnid = -1;
			if (wifiInfo != null) {
				cssid = wifiInfo.getSSID() == null ? "unknown" : wifiInfo.getSSID().replace("\"", "");
				cnid = wifiInfo.getNetworkId();
			}

			if (wificonfiglist != null && wificonfiglist.size() > 0) {
				for (WifiConfiguration wifiConfiguration : wificonfiglist) {
					JSONObject item = new JSONObject();

					String nametemp = wifiConfiguration.SSID == null ? "" : wifiConfiguration.SSID.replace("\"", "");
					int nid = wifiConfiguration.networkId;
					// 排除当前连接WiFi条目
					if (nametemp.equals(cssid) && nid == cnid) {
						continue;
					}
					String mactemp = wifiConfiguration.BSSID == null ? "" : wifiConfiguration.BSSID.toString();
					item.put("ssid", URLEncoder.encode(nametemp, "UTF-8"));
					item.put("bssid", URLEncoder.encode(mactemp, "UTF-8"));
					aplist.put(item);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (!TextUtils.isEmpty(aplist.toString())) {
			return aplist.toString();
		}
		return "";
	}

	public static String getNetworkInterval(Context ctx) {
		JSONArray aplist = new JSONArray();

		try {
			String type = "";
			ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
			NetworkInfo info = cm.getActiveNetworkInfo();
			if (info == null || !info.isAvailable()) {
				JSONObject item = new JSONObject();
				type = "unkonw";
				item.put(type, System.currentTimeMillis() + "");
				aplist.put(item);
			} else if (info.getType() == ConnectivityManager.TYPE_WIFI) {
				JSONObject item = new JSONObject();
				type = "wifi";
				item.put(type, System.currentTimeMillis() + "");
				aplist.put(item);
			} else if (info.getType() == ConnectivityManager.TYPE_MOBILE) {
				int subType = info.getSubtype();
				if (subType == TelephonyManager.NETWORK_TYPE_CDMA || subType == TelephonyManager.NETWORK_TYPE_GPRS
						|| subType == TelephonyManager.NETWORK_TYPE_EDGE) {
					JSONObject item = new JSONObject();
					type = "2g";
					item.put(type, System.currentTimeMillis() + "");
					aplist.put(item);
				} else if (subType == TelephonyManager.NETWORK_TYPE_UMTS
						|| subType == TelephonyManager.NETWORK_TYPE_HSDPA
						|| subType == TelephonyManager.NETWORK_TYPE_EVDO_A
						|| subType == TelephonyManager.NETWORK_TYPE_EVDO_0
						|| subType == TelephonyManager.NETWORK_TYPE_EVDO_B
						|| subType == TelephonyManager.NETWORK_TYPE_HSPA
						|| subType == TelephonyManager.NETWORK_TYPE_HSUPA
						|| subType == TelephonyManager.NETWORK_TYPE_EHRPD
						|| subType == TelephonyManager.NETWORK_TYPE_HSPAP) {
					JSONObject item = new JSONObject();
					type = "3g";
					item.put(type, System.currentTimeMillis() + "");
					aplist.put(item);
				} else if (subType == TelephonyManager.NETWORK_TYPE_LTE) {// LTE是3g到4g的过渡，是3.9G的全球标准
					JSONObject item = new JSONObject();
					type = "4g";
					item.put(type, System.currentTimeMillis() + "");
					aplist.put(item);
				}
			}

		} catch (Exception e) {
			return "";
		}
		if (!TextUtils.isEmpty(aplist.toString())) {
			return aplist.toString();
		}
		return "";
	}

	/**
	 * 获取当前正在运行的进程
	 */
	public static String getCurProcessList(Context context) {
		try {
			ActivityManager mActivityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
			JSONArray aplist = new JSONArray();
			for (RunningAppProcessInfo appProcess : mActivityManager.getRunningAppProcesses()) {
				JSONObject item = new JSONObject();
				item.put("importance", appProcess.importance + "");
				item.put("importanceReasonCode", appProcess.importanceReasonCode + "");
				item.put("importanceReasonPid", appProcess.importanceReasonPid + "");
				item.put("lastTrimLevel", appProcess.lastTrimLevel + "");
				item.put("lru", appProcess.lru + "");
				item.put("pid", appProcess.pid + "");
				item.put("processName", appProcess.processName + "");
				item.put("uid", appProcess.uid + "");
				aplist.put(item);
			}
			if (!TextUtils.isEmpty(aplist.toString())) {
				return aplist.toString();
			}
			return "";
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * 通过Runtime方式获取WiFi Mac地址
	 * 
	 * @return
	 */
	private static final String MAC1_CMD = "cat /sys/class/net/wlan0/address";

	public static String collectMacAddressWithRuntime() {
		String macaddress = "";
		Process process = null;
		BufferedReader br = null;
		try {
			process = Runtime.getRuntime().exec(MAC1_CMD);

			if (process != null) {
				br = new BufferedReader(new InputStreamReader(process.getInputStream(), "GBK"));
				String wifi = br.readLine();
				// debug("mac1:" + wifi);
				if (wifi != null) {
					macaddress = wifi;
				}
			}

		} catch (Exception e) {
			//e.printStackTrace();
		} finally {
//			if (process != null) {
//				try {
//					process.destroy();
//				} catch (Exception e) {
//				}
//				// process.exitValue(); // use exitValue() to determine if process is still running.
//			}
			try {
				if (process != null) {
					// use exitValue() to determine if process is still running.
					process.exitValue();
				}
			} catch (IllegalThreadStateException e) {
				// process is still running, kill it.
				process.destroy();
			} 
			if (br != null) {
				try {
					br.close();
				} catch (Exception e) {
					// e.printStackTrace();
				}
				br = null;
			}
		}

		return macaddress;
	}

	@SuppressLint("NewApi")
	public static String getCellInfo(Context ctx) {
		try {
//			if (!ManagerUtils.checkPermission(ctx, Manifest.permission.ACCESS_COARSE_LOCATION)) {
//				return "";
//			}
			TelephonyManager tManager = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
			// 获取封装了基站信息的GsmCellLaction对象(需要ACCESS_COARSE_LACTION或者ACCESS_FINE_LACTION权限)
			// 返回值MCC + MNC
			String operator = tManager.getNetworkOperator();
			if (TextUtils.isEmpty(operator)) {
				return "";
			}
			Object obj = tManager.getCellLocation();
			if (obj instanceof CdmaCellLocation) {
				CdmaCellLocation location = (CdmaCellLocation) tManager.getCellLocation();
				if (location == null)
					throw new Exception("errr");
				int cellIDs = location.getBaseStationId();
				int networkID = location.getNetworkId();
				StringBuilder sb = new StringBuilder();
				sb.append(location.getSystemId());
				JSONObject jo = new JSONObject();
				jo.put("bid", cellIDs);
				jo.put("nid", networkID);
				jo.put("sid", sb.toString());
				jo.put("latitude", location.getBaseStationLatitude() + "");
				jo.put("longitude", location.getBaseStationLongitude() + "");
				return jo.toString();
			} else if (obj instanceof GsmCellLocation) {
				GsmCellLocation location = (GsmCellLocation) tManager.getCellLocation();
				if (location == null)
					throw new Exception("errr");
				int lac = location.getLac();
				JSONObject jo = new JSONObject();
				jo.put("cid", location.getCid());
				jo.put("lac", lac);
				jo.put("psc", location.getPsc());
				return jo.toString();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}
	public static String getCellNeighborInfo(Context ctx) {
		JSONArray cellList = new JSONArray();
		try {
			TelephonyManager tManager = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
			List<NeighboringCellInfo> infos = tManager.getNeighboringCellInfo();
			for (NeighboringCellInfo info : infos) { // 根据邻区总数进行循环
				JSONObject jo = new JSONObject();
				jo.put("lac", info.getLac());
				jo.put("cid", info.getCid());
				jo.put("bsss", (-113 + 2 * info.getRssi()));
				jo.put("networkType", info.getNetworkType());
				jo.put("psc", info.getPsc());
				cellList.put(jo);
			}
		} catch (Exception e) {
			return "";
		}
		if (!TextUtils.isEmpty(cellList.toString())) {
			return cellList.toString();
		}
		return "";
	}
	/**
	 * 初次获取设备唯一标识,经过md5处理
	 */
	public static String getAndroidId(Context mContext) {
		try {
			if (selfPermissionGranted(mContext, Manifest.permission.READ_PHONE_STATE)) {
				String android_id = Secure.getString(mContext.getContentResolver(), Secure.ANDROID_ID);
				return android_id;
			} else {
				return "";
			}
		} catch (Exception e) {
			e.printStackTrace();
			return "";
		}
	}

	public static String getAppFirstInstallTime(Context ctx) {
		try {
			PackageManager packageManager = ctx.getPackageManager();
			try {
				PackageInfo packageInfo = packageManager.getPackageInfo(ctx.getPackageName(), 0);
				String str= packageInfo.firstInstallTime + "";// 应用第一次安装的时间
				if(TextUtils.isEmpty(str)){
					return  System.currentTimeMillis()+"";
				}
				return str;
			} catch (Exception e) {
				e.printStackTrace();
			}
			return System.currentTimeMillis()+"";
		} catch (Exception e) {
			e.printStackTrace();
			return  System.currentTimeMillis()+"";
		}
	}
	public static String getDeviceTraffics(Context ctx) {
		try {
			PackageManager pm = ctx.getPackageManager();
			List<ApplicationInfo> appliactaionInfos = pm.getInstalledApplications(0);
			JSONArray arrays = new JSONArray();
			for (ApplicationInfo info : appliactaionInfos) {
				int uid = info.uid; // 获得软件uid
				JSONObject jo = new JSONObject();
				jo.put("uid", info.uid);
				jo.put("tx", TrafficStats.getUidTxBytes(uid));// 上传流量
				jo.put("rx", TrafficStats.getUidRxBytes(uid));// 下载流量
				jo.put("packageName", info.packageName);
				arrays.put(jo);
			}
			// sb.append("total 2g/3g tx:" + TrafficStats.getMobileTxBytes());//
			// 获取手机3g/2g网络上传的总流量
			// sb.append("total 2g/3g rx:" + TrafficStats.getMobileRxBytes());//
			// 手机2g/3g下载的总流量
			//
			// sb.append("total tx:" + TrafficStats.getTotalTxBytes());//
			// 手机全部网络接口
			// // 包括wifi，3g、2g上传的总流量
			// sb.append("total rx:" + TrafficStats.getTotalRxBytes());//
			// 手机全部网络接口
			// 包括wifi，3g、2g下载的总流量</applicationinfo>
			if (!TextUtils.isEmpty(arrays.toString())) {
				return arrays.toString();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}
}
