use crate::engine::{start_json, Scan};
use crate::sweep::Protect;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jint, jlong, jstring};
use jni::{JNIEnv, JavaVM};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

fn protector(env: &mut JNIEnv, obj: &JObject) -> Option<Protect> {
    if obj.is_null() {
        return None;
    }
    let vm: JavaVM = env.get_java_vm().ok()?;
    let target: GlobalRef = env.new_global_ref(obj).ok()?;
    let vm = Arc::new(vm);
    Some(Arc::new(move |fd: i64| -> bool {
        let Ok(mut env) = vm.attach_current_thread_permanently() else {
            return false;
        };
        let ok = env
            .call_method(target.as_obj(), "protect", "(I)Z", &[JValue::Int(fd as i32)])
            .and_then(|v| v.z())
            .unwrap_or(false);
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        ok
    }))
}

#[no_mangle]
pub extern "system" fn Java_dev_cluvex_zedsecure_scan_ZedScanNative_start<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    config: JString<'l>,
    protect: JObject<'l>,
) -> jlong {
    let cfg: String = match env.get_string(&config) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let p = protector(&mut env, &protect);
    match catch_unwind(AssertUnwindSafe(|| start_json(&cfg, p))) {
        Ok(Ok(scan)) => Box::into_raw(Box::new(scan)) as jlong,
        Ok(Err(e)) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", e);
            0
        }
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalStateException", "zedscan could not start");
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_cluvex_zedsecure_scan_ZedScanNative_poll<'l>(
    env: JNIEnv<'l>,
    _class: JClass<'l>,
    handle: jlong,
    wait_ms: jint,
) -> jstring {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    let scan = unsafe { &*(handle as *const Scan) };
    let wait = Duration::from_millis(wait_ms.clamp(0, 60_000) as u64);
    let events = match catch_unwind(AssertUnwindSafe(|| scan.poll(wait, 4000))) {
        Ok(Some(events)) => events,
        _ => return std::ptr::null_mut(),
    };
    match serde_json::to_string(&events) {
        Ok(s) => env.new_string(s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_cluvex_zedsecure_scan_ZedScanNative_stop<'l>(_env: JNIEnv<'l>, _class: JClass<'l>, handle: jlong) {
    if handle != 0 {
        let scan = unsafe { &*(handle as *const Scan) };
        scan.stop();
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_cluvex_zedsecure_scan_ZedScanNative_free<'l>(_env: JNIEnv<'l>, _class: JClass<'l>, handle: jlong) {
    if handle != 0 {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe { drop(Box::from_raw(handle as *mut Scan)) }));
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_cluvex_zedsecure_scan_ZedScanNative_countryGroups<'l>(
    mut env: JNIEnv<'l>,
    _class: JClass<'l>,
    geoip: JString<'l>,
    codes: JString<'l>,
) -> jstring {
    let path: String = match env.get_string(&geoip) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let list: String = match env.get_string(&codes) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let codes: Vec<String> = list.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
    match catch_unwind(AssertUnwindSafe(|| crate::engine::country_groups(&path, &codes))) {
        Ok(Ok(json)) => env.new_string(json).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_dev_cluvex_zedsecure_scan_ZedScanNative_version<'l>(env: JNIEnv<'l>, _class: JClass<'l>) -> jstring {
    env.new_string(crate::VERSION).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
}
