//! JNI (Java Native Interface) bindings for Android.
//!
//! This module provides JNI-compatible functions that can be called directly
//! from Kotlin/Java on Android.

// JNI bindings will be implemented when Android support is added.
// For now, this is a placeholder to allow the jni feature to compile.

#[cfg(feature = "jni")]
use std::os::raw::c_void;

/// Placeholder for JNI environment pointer type
#[cfg(feature = "jni")]
pub type JNIEnv = *mut c_void;

/// Placeholder for JNI class type  
#[cfg(feature = "jni")]
pub type JClass = *mut c_void;

/// Placeholder for JNI object type
#[cfg(feature = "jni")]
pub type JObject = *mut c_void;

/// Placeholder for JNI string type
#[cfg(feature = "jni")]
pub type JString = *mut c_void;

/// Placeholder for JNI byte array type
#[cfg(feature = "jni")]
pub type JByteArray = *mut c_void;

// TODO: Implement actual JNI bindings using the jni crate:
//
// #[no_mangle]
// pub extern "system" fn Java_com_softether_vpn_SoftEtherBridge_create(
//     env: JNIEnv,
//     _class: JClass,
//     config: JObject,
// ) -> jlong {
//     // Implementation
// }
