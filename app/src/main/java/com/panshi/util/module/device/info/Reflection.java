package com.panshi.util.module.device.info;

import android.content.Context;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * 反射工具类
 */
public class Reflection {

	public static String getPlayAdId(Context context) {
		try {
			Object AdvertisingInfoObject = getAdvertisingInfoObject(context);

			String playAdid = (String) invokeInstanceMethod(
					AdvertisingInfoObject, "getId", null);

			return playAdid;
		} catch (Throwable t) {
			return null;
		}
	}
	public static boolean getContextCompat(Context ctx){
		try{
			Class classObject = Class.forName("android.support.v4.content.ContextCompat");
			if(classObject!=null){
				return true;
			}
		}catch(Exception e){
			return false;
		}
		return false;
	}
	public static int getContextCompatValue(Context ctx,String permissions){
		try{
			Class classObject = Class.forName("android.support.v4.content.ContextCompat");
			Method staticMethod = classObject.getDeclaredMethod("checkSelfPermission",Context.class,String.class);  
			return (Integer) staticMethod.invoke(classObject,ctx,permissions);//这里不需要newInstance  
		}catch(Exception e){
			return 0;
		}
	}
	
	public static boolean checkV4Pair(Context context) {
		try {
			Class<?> classObject = Class.forName("android.support.v4.util.Pair");
			if (classObject != null) {
				return true;
			}
		} catch (Exception e) {
			return false;
		}
		return false;
	}
	
	public static boolean isGooglePlayServicesAvailable(Context context) {
		try {
			Integer isGooglePlayServicesAvailableStatusCode = (Integer) invokeStaticMethod(
					"com.google.android.gms.common.GooglePlayServicesUtil",
					"isGooglePlayServicesAvailable",
					new Class[] { Context.class }, context);

			boolean isGooglePlayServicesAvailable = (Boolean) isConnectionResultSuccess(isGooglePlayServicesAvailableStatusCode);

			return isGooglePlayServicesAvailable;
		} catch (Throwable t) {
			return false;
		}
	}

	public static String getMacAddress(Context context) {
		try {
			String macSha1 = (String) invokeStaticMethod(
					"com.admaster.square.utils.MacAddressUtil", "getMacAddress",
					new Class[] { Context.class }, context);

			return macSha1;
		} catch (Throwable t) {
			return null;
		}
	}

	private static Object getAdvertisingInfoObject(Context context)
			throws Exception {
		return invokeStaticMethod(
				"com.google.android.gms.ads.identifier.AdvertisingIdClient",
				"getAdvertisingIdInfo", new Class[] { Context.class }, context);
	}
	
	private static boolean isConnectionResultSuccess(Integer statusCode) {
		if (statusCode == null) {
			return false;
		}

		try {
			Class ConnectionResultClass = Class
					.forName("com.google.android.gms.common.ConnectionResult");

			Field SuccessField = ConnectionResultClass.getField("SUCCESS");

			int successStatusCode = SuccessField.getInt(null);

			return successStatusCode == statusCode;
		} catch (Throwable t) {
			return false;
		}
	}

	public static Class forName(String className) {
		try {
			Class classObject = Class.forName(className);
			return classObject;
		} catch (Throwable t) {
			return null;
		}
	}

	public static Object createDefaultInstance(String className) {
		Class classObject = forName(className);
		Object instance = createDefaultInstance(classObject);
		return instance;
	}

	public static Object createDefaultInstance(Class classObject) {
		try {
			Object instance = classObject.newInstance();
			return instance;
		} catch (Throwable t) {
			return null;
		}
	}

	public static Object createInstance(String className, Class[] cArgs,
			Object... args) {
		try {
			Class classObject = Class.forName(className);
			@SuppressWarnings("unchecked")
			Constructor constructor = classObject.getConstructor(cArgs);
			Object instance = constructor.newInstance(args);
			return instance;
		} catch (Throwable t) {
			return null;
		}
	}

	public static Object invokeStaticMethod(String className,
			String methodName, Class[] cArgs, Object... args) throws Exception {
		Class classObject = Class.forName(className);
		return invokeMethod(classObject, methodName, null, cArgs, args);
	}

	public static Object invokeInstanceMethod(Object instance,
			String methodName, Class[] cArgs, Object... args) throws Exception {
		Class classObject = instance.getClass();

		return invokeMethod(classObject, methodName, instance, cArgs, args);
	}

	public static Object invokeMethod(Class classObject, String methodName,
			Object instance, Class[] cArgs, Object... args) throws Exception {
		@SuppressWarnings("unchecked")
		Method methodObject = classObject.getMethod(methodName, cArgs);

		Object resultObject = methodObject.invoke(instance, args);

		return resultObject;
	}

}
