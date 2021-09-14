typedef __builtin_va_list __gnuc_va_list;
typedef __gnuc_va_list va_list;
typedef unsigned char jboolean;
typedef char jbyte;
typedef unsigned short jchar;
typedef short jshort;
typedef int jint;
typedef long long jlong;
typedef float jfloat;
typedef double jdouble;



typedef jint jsize;
typedef void* jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jarray;
typedef jarray jobjectArray;
typedef jarray jbooleanArray;
typedef jarray jbyteArray;
typedef jarray jcharArray;
typedef jarray jshortArray;
typedef jarray jintArray;
typedef jarray jlongArray;
typedef jarray jfloatArray;
typedef jarray jdoubleArray;
typedef jobject jthrowable;
typedef jobject jweak;



struct _jfieldID {};
typedef struct _jfieldID* jfieldID;

struct _jmethodID {};
typedef struct _jmethodID* jmethodID;

struct JNIInvokeInterface;

typedef struct {
    jobject l;
} jvalue;

typedef enum {
    JNIInvalidRefType = 0,
    JNILocalRefType = 1,
    JNIGlobalRefType = 2,
    JNIWeakGlobalRefType = 3
} jobjectRefType;

typedef struct {
    const char* name;
    const char* signature;
    void* fnPtr;
} JNINativeMethod;

struct _JNIEnv;
struct _JavaVM;
typedef const struct JNINativeInterface* C_JNIEnv;





typedef const struct JNINativeInterface* JNIEnv;
typedef const struct JNIInvokeInterface* JavaVM;





struct JNINativeInterface {
    void* reserved0;
    void* reserved1;
    void* reserved2;
    void* reserved3;

    jint (*GetVersion)(JNIEnv *);

    jclass (*DefineClass)(JNIEnv*, const char*, jobject, const jbyte*,
                        jsize);
    jclass (*FindClass)(JNIEnv*, const char*);

    jmethodID (*FromReflectedMethod)(JNIEnv*, jobject);
    jfieldID (*FromReflectedField)(JNIEnv*, jobject);

    jobject (*ToReflectedMethod)(JNIEnv*, jclass, jmethodID, jboolean);

    jclass (*GetSuperclass)(JNIEnv*, jclass);
    jboolean (*IsAssignableFrom)(JNIEnv*, jclass, jclass);


    jobject (*ToReflectedField)(JNIEnv*, jclass, jfieldID, jboolean);

    jint (*Throw)(JNIEnv*, jthrowable);
    jint (*ThrowNew)(JNIEnv *, jclass, const char *);
    jthrowable (*ExceptionOccurred)(JNIEnv*);
    void (*ExceptionDescribe)(JNIEnv*);
    void (*ExceptionClear)(JNIEnv*);
    void (*FatalError)(JNIEnv*, const char*);

    jint (*PushLocalFrame)(JNIEnv*, jint);
    jobject (*PopLocalFrame)(JNIEnv*, jobject);

    jobject (*NewGlobalRef)(JNIEnv*, jobject);
    void (*DeleteGlobalRef)(JNIEnv*, jobject);
    void (*DeleteLocalRef)(JNIEnv*, jobject);
    jboolean (*IsSameObject)(JNIEnv*, jobject, jobject);

    jobject (*NewLocalRef)(JNIEnv*, jobject);
    jint (*EnsureLocalCapacity)(JNIEnv*, jint);

    jobject (*AllocObject)(JNIEnv*, jclass);
    jobject (*NewObject)(JNIEnv*, jclass, jmethodID, ...);
    jobject (*NewObjectV)(JNIEnv*, jclass, jmethodID, va_list);
    jobject (*NewObjectA)(JNIEnv*, jclass, jmethodID, jvalue*);

    jclass (*GetObjectClass)(JNIEnv*, jobject);
    jboolean (*IsInstanceOf)(JNIEnv*, jobject, jclass);
    jmethodID (*GetMethodID)(JNIEnv*, jclass, const char*, const char*);

    jobject (*CallObjectMethod)(JNIEnv*, jobject, jmethodID, ...);
    jobject (*CallObjectMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    jobject (*CallObjectMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    jboolean (*CallBooleanMethod)(JNIEnv*, jobject, jmethodID, ...);
    jboolean (*CallBooleanMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    jboolean (*CallBooleanMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    jbyte (*CallByteMethod)(JNIEnv*, jobject, jmethodID, ...);
    jbyte (*CallByteMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    jbyte (*CallByteMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    jchar (*CallCharMethod)(JNIEnv*, jobject, jmethodID, ...);
    jchar (*CallCharMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    jchar (*CallCharMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    jshort (*CallShortMethod)(JNIEnv*, jobject, jmethodID, ...);
    jshort (*CallShortMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    jshort (*CallShortMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    jint (*CallIntMethod)(JNIEnv*, jobject, jmethodID, ...);
    jint (*CallIntMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    jint (*CallIntMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    jlong (*CallLongMethod)(JNIEnv*, jobject, jmethodID, ...);
    jlong (*CallLongMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    jlong (*CallLongMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);
    jfloat (*CallFloatMethod)(JNIEnv*, jobject, jmethodID, ...) ;
    jfloat (*CallFloatMethodV)(JNIEnv*, jobject, jmethodID, va_list) ;
    jfloat (*CallFloatMethodA)(JNIEnv*, jobject, jmethodID, jvalue*) ;
    jdouble (*CallDoubleMethod)(JNIEnv*, jobject, jmethodID, ...) ;
    jdouble (*CallDoubleMethodV)(JNIEnv*, jobject, jmethodID, va_list) ;
    jdouble (*CallDoubleMethodA)(JNIEnv*, jobject, jmethodID, jvalue*) ;
    void (*CallVoidMethod)(JNIEnv*, jobject, jmethodID, ...);
    void (*CallVoidMethodV)(JNIEnv*, jobject, jmethodID, va_list);
    void (*CallVoidMethodA)(JNIEnv*, jobject, jmethodID, jvalue*);

    jobject (*CallNonvirtualObjectMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...);
    jobject (*CallNonvirtualObjectMethodV)(JNIEnv*, jobject, jclass,
                        jmethodID, va_list);
    jobject (*CallNonvirtualObjectMethodA)(JNIEnv*, jobject, jclass,
                        jmethodID, jvalue*);
    jboolean (*CallNonvirtualBooleanMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...);
    jboolean (*CallNonvirtualBooleanMethodV)(JNIEnv*, jobject, jclass,
                         jmethodID, va_list);
    jboolean (*CallNonvirtualBooleanMethodA)(JNIEnv*, jobject, jclass,
                         jmethodID, jvalue*);
    jbyte (*CallNonvirtualByteMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...);
    jbyte (*CallNonvirtualByteMethodV)(JNIEnv*, jobject, jclass,
                        jmethodID, va_list);
    jbyte (*CallNonvirtualByteMethodA)(JNIEnv*, jobject, jclass,
                        jmethodID, jvalue*);
    jchar (*CallNonvirtualCharMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...);
    jchar (*CallNonvirtualCharMethodV)(JNIEnv*, jobject, jclass,
                        jmethodID, va_list);
    jchar (*CallNonvirtualCharMethodA)(JNIEnv*, jobject, jclass,
                        jmethodID, jvalue*);
    jshort (*CallNonvirtualShortMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...);
    jshort (*CallNonvirtualShortMethodV)(JNIEnv*, jobject, jclass,
                        jmethodID, va_list);
    jshort (*CallNonvirtualShortMethodA)(JNIEnv*, jobject, jclass,
                        jmethodID, jvalue*);
    jint (*CallNonvirtualIntMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...);
    jint (*CallNonvirtualIntMethodV)(JNIEnv*, jobject, jclass,
                        jmethodID, va_list);
    jint (*CallNonvirtualIntMethodA)(JNIEnv*, jobject, jclass,
                        jmethodID, jvalue*);
    jlong (*CallNonvirtualLongMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...);
    jlong (*CallNonvirtualLongMethodV)(JNIEnv*, jobject, jclass,
                        jmethodID, va_list);
    jlong (*CallNonvirtualLongMethodA)(JNIEnv*, jobject, jclass,
                        jmethodID, jvalue*);
    jfloat (*CallNonvirtualFloatMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...) ;
    jfloat (*CallNonvirtualFloatMethodV)(JNIEnv*, jobject, jclass,
                        jmethodID, va_list) ;
    jfloat (*CallNonvirtualFloatMethodA)(JNIEnv*, jobject, jclass,
                        jmethodID, jvalue*) ;
    jdouble (*CallNonvirtualDoubleMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...) ;
    jdouble (*CallNonvirtualDoubleMethodV)(JNIEnv*, jobject, jclass,
                        jmethodID, va_list) ;
    jdouble (*CallNonvirtualDoubleMethodA)(JNIEnv*, jobject, jclass,
                        jmethodID, jvalue*) ;
    void (*CallNonvirtualVoidMethod)(JNIEnv*, jobject, jclass,
                        jmethodID, ...);
    void (*CallNonvirtualVoidMethodV)(JNIEnv*, jobject, jclass,
                        jmethodID, va_list);
    void (*CallNonvirtualVoidMethodA)(JNIEnv*, jobject, jclass,
                        jmethodID, jvalue*);

    jfieldID (*GetFieldID)(JNIEnv*, jclass, const char*, const char*);

    jobject (*GetObjectField)(JNIEnv*, jobject, jfieldID);
    jboolean (*GetBooleanField)(JNIEnv*, jobject, jfieldID);
    jbyte (*GetByteField)(JNIEnv*, jobject, jfieldID);
    jchar (*GetCharField)(JNIEnv*, jobject, jfieldID);
    jshort (*GetShortField)(JNIEnv*, jobject, jfieldID);
    jint (*GetIntField)(JNIEnv*, jobject, jfieldID);
    jlong (*GetLongField)(JNIEnv*, jobject, jfieldID);
    jfloat (*GetFloatField)(JNIEnv*, jobject, jfieldID) ;
    jdouble (*GetDoubleField)(JNIEnv*, jobject, jfieldID) ;

    void (*SetObjectField)(JNIEnv*, jobject, jfieldID, jobject);
    void (*SetBooleanField)(JNIEnv*, jobject, jfieldID, jboolean);
    void (*SetByteField)(JNIEnv*, jobject, jfieldID, jbyte);
    void (*SetCharField)(JNIEnv*, jobject, jfieldID, jchar);
    void (*SetShortField)(JNIEnv*, jobject, jfieldID, jshort);
    void (*SetIntField)(JNIEnv*, jobject, jfieldID, jint);
    void (*SetLongField)(JNIEnv*, jobject, jfieldID, jlong);
    void (*SetFloatField)(JNIEnv*, jobject, jfieldID, jfloat) ;
    void (*SetDoubleField)(JNIEnv*, jobject, jfieldID, jdouble) ;

    jmethodID (*GetStaticMethodID)(JNIEnv*, jclass, const char*, const char*);

    jobject (*CallStaticObjectMethod)(JNIEnv*, jclass, jmethodID, ...);
    jobject (*CallStaticObjectMethodV)(JNIEnv*, jclass, jmethodID, va_list);
    jobject (*CallStaticObjectMethodA)(JNIEnv*, jclass, jmethodID, jvalue*);
    jboolean (*CallStaticBooleanMethod)(JNIEnv*, jclass, jmethodID, ...);
    jboolean (*CallStaticBooleanMethodV)(JNIEnv*, jclass, jmethodID,
                        va_list);
    jboolean (*CallStaticBooleanMethodA)(JNIEnv*, jclass, jmethodID,
                        jvalue*);
    jbyte (*CallStaticByteMethod)(JNIEnv*, jclass, jmethodID, ...);
    jbyte (*CallStaticByteMethodV)(JNIEnv*, jclass, jmethodID, va_list);
    jbyte (*CallStaticByteMethodA)(JNIEnv*, jclass, jmethodID, jvalue*);
    jchar (*CallStaticCharMethod)(JNIEnv*, jclass, jmethodID, ...);
    jchar (*CallStaticCharMethodV)(JNIEnv*, jclass, jmethodID, va_list);
    jchar (*CallStaticCharMethodA)(JNIEnv*, jclass, jmethodID, jvalue*);
    jshort (*CallStaticShortMethod)(JNIEnv*, jclass, jmethodID, ...);
    jshort (*CallStaticShortMethodV)(JNIEnv*, jclass, jmethodID, va_list);
    jshort (*CallStaticShortMethodA)(JNIEnv*, jclass, jmethodID, jvalue*);
    jint (*CallStaticIntMethod)(JNIEnv*, jclass, jmethodID, ...);
    jint (*CallStaticIntMethodV)(JNIEnv*, jclass, jmethodID, va_list);
    jint (*CallStaticIntMethodA)(JNIEnv*, jclass, jmethodID, jvalue*);
    jlong (*CallStaticLongMethod)(JNIEnv*, jclass, jmethodID, ...);
    jlong (*CallStaticLongMethodV)(JNIEnv*, jclass, jmethodID, va_list);
    jlong (*CallStaticLongMethodA)(JNIEnv*, jclass, jmethodID, jvalue*);
    jfloat (*CallStaticFloatMethod)(JNIEnv*, jclass, jmethodID, ...) ;
    jfloat (*CallStaticFloatMethodV)(JNIEnv*, jclass, jmethodID, va_list) ;
    jfloat (*CallStaticFloatMethodA)(JNIEnv*, jclass, jmethodID, jvalue*) ;
    jdouble (*CallStaticDoubleMethod)(JNIEnv*, jclass, jmethodID, ...) ;
    jdouble (*CallStaticDoubleMethodV)(JNIEnv*, jclass, jmethodID, va_list) ;
    jdouble (*CallStaticDoubleMethodA)(JNIEnv*, jclass, jmethodID, jvalue*) ;
    void (*CallStaticVoidMethod)(JNIEnv*, jclass, jmethodID, ...);
    void (*CallStaticVoidMethodV)(JNIEnv*, jclass, jmethodID, va_list);
    void (*CallStaticVoidMethodA)(JNIEnv*, jclass, jmethodID, jvalue*);

    jfieldID (*GetStaticFieldID)(JNIEnv*, jclass, const char*,
                        const char*);

    jobject (*GetStaticObjectField)(JNIEnv*, jclass, jfieldID);
    jboolean (*GetStaticBooleanField)(JNIEnv*, jclass, jfieldID);
    jbyte (*GetStaticByteField)(JNIEnv*, jclass, jfieldID);
    jchar (*GetStaticCharField)(JNIEnv*, jclass, jfieldID);
    jshort (*GetStaticShortField)(JNIEnv*, jclass, jfieldID);
    jint (*GetStaticIntField)(JNIEnv*, jclass, jfieldID);
    jlong (*GetStaticLongField)(JNIEnv*, jclass, jfieldID);
    jfloat (*GetStaticFloatField)(JNIEnv*, jclass, jfieldID) ;
    jdouble (*GetStaticDoubleField)(JNIEnv*, jclass, jfieldID) ;

    void (*SetStaticObjectField)(JNIEnv*, jclass, jfieldID, jobject);
    void (*SetStaticBooleanField)(JNIEnv*, jclass, jfieldID, jboolean);
    void (*SetStaticByteField)(JNIEnv*, jclass, jfieldID, jbyte);
    void (*SetStaticCharField)(JNIEnv*, jclass, jfieldID, jchar);
    void (*SetStaticShortField)(JNIEnv*, jclass, jfieldID, jshort);
    void (*SetStaticIntField)(JNIEnv*, jclass, jfieldID, jint);
    void (*SetStaticLongField)(JNIEnv*, jclass, jfieldID, jlong);
    void (*SetStaticFloatField)(JNIEnv*, jclass, jfieldID, jfloat) ;
    void (*SetStaticDoubleField)(JNIEnv*, jclass, jfieldID, jdouble) ;

    jstring (*NewString)(JNIEnv*, const jchar*, jsize);
    jsize (*GetStringLength)(JNIEnv*, jstring);
    const jchar* (*GetStringChars)(JNIEnv*, jstring, jboolean*);
    void (*ReleaseStringChars)(JNIEnv*, jstring, const jchar*);
    jstring (*NewStringUTF)(JNIEnv*, const char*);
    jsize (*GetStringUTFLength)(JNIEnv*, jstring);

    const char* (*GetStringUTFChars)(JNIEnv*, jstring, jboolean*);
    void (*ReleaseStringUTFChars)(JNIEnv*, jstring, const char*);
    jsize (*GetArrayLength)(JNIEnv*, jarray);
    jobjectArray (*NewObjectArray)(JNIEnv*, jsize, jclass, jobject);
    jobject (*GetObjectArrayElement)(JNIEnv*, jobjectArray, jsize);
    void (*SetObjectArrayElement)(JNIEnv*, jobjectArray, jsize, jobject);

    jbooleanArray (*NewBooleanArray)(JNIEnv*, jsize);
    jbyteArray (*NewByteArray)(JNIEnv*, jsize);
    jcharArray (*NewCharArray)(JNIEnv*, jsize);
    jshortArray (*NewShortArray)(JNIEnv*, jsize);
    jintArray (*NewIntArray)(JNIEnv*, jsize);
    jlongArray (*NewLongArray)(JNIEnv*, jsize);
    jfloatArray (*NewFloatArray)(JNIEnv*, jsize);
    jdoubleArray (*NewDoubleArray)(JNIEnv*, jsize);

    jboolean* (*GetBooleanArrayElements)(JNIEnv*, jbooleanArray, jboolean*);
    jbyte* (*GetByteArrayElements)(JNIEnv*, jbyteArray, jboolean*);
    jchar* (*GetCharArrayElements)(JNIEnv*, jcharArray, jboolean*);
    jshort* (*GetShortArrayElements)(JNIEnv*, jshortArray, jboolean*);
    jint* (*GetIntArrayElements)(JNIEnv*, jintArray, jboolean*);
    jlong* (*GetLongArrayElements)(JNIEnv*, jlongArray, jboolean*);
    jfloat* (*GetFloatArrayElements)(JNIEnv*, jfloatArray, jboolean*);
    jdouble* (*GetDoubleArrayElements)(JNIEnv*, jdoubleArray, jboolean*);

    void (*ReleaseBooleanArrayElements)(JNIEnv*, jbooleanArray,
                        jboolean*, jint);
    void (*ReleaseByteArrayElements)(JNIEnv*, jbyteArray,
                        jbyte*, jint);
    void (*ReleaseCharArrayElements)(JNIEnv*, jcharArray,
                        jchar*, jint);
    void (*ReleaseShortArrayElements)(JNIEnv*, jshortArray,
                        jshort*, jint);
    void (*ReleaseIntArrayElements)(JNIEnv*, jintArray,
                        jint*, jint);
    void (*ReleaseLongArrayElements)(JNIEnv*, jlongArray,
                        jlong*, jint);
    void (*ReleaseFloatArrayElements)(JNIEnv*, jfloatArray,
                        jfloat*, jint);
    void (*ReleaseDoubleArrayElements)(JNIEnv*, jdoubleArray,
                        jdouble*, jint);

    void (*GetBooleanArrayRegion)(JNIEnv*, jbooleanArray,
                        jsize, jsize, jboolean*);
    void (*GetByteArrayRegion)(JNIEnv*, jbyteArray,
                        jsize, jsize, jbyte*);
    void (*GetCharArrayRegion)(JNIEnv*, jcharArray,
                        jsize, jsize, jchar*);
    void (*GetShortArrayRegion)(JNIEnv*, jshortArray,
                        jsize, jsize, jshort*);
    void (*GetIntArrayRegion)(JNIEnv*, jintArray,
                        jsize, jsize, jint*);
    void (*GetLongArrayRegion)(JNIEnv*, jlongArray,
                        jsize, jsize, jlong*);
    void (*GetFloatArrayRegion)(JNIEnv*, jfloatArray,
                        jsize, jsize, jfloat*);
    void (*GetDoubleArrayRegion)(JNIEnv*, jdoubleArray,
                        jsize, jsize, jdouble*);


    void (*SetBooleanArrayRegion)(JNIEnv*, jbooleanArray,
                        jsize, jsize, const jboolean*);
    void (*SetByteArrayRegion)(JNIEnv*, jbyteArray,
                        jsize, jsize, const jbyte*);
    void (*SetCharArrayRegion)(JNIEnv*, jcharArray,
                        jsize, jsize, const jchar*);
    void (*SetShortArrayRegion)(JNIEnv*, jshortArray,
                        jsize, jsize, const jshort*);
    void (*SetIntArrayRegion)(JNIEnv*, jintArray,
                        jsize, jsize, const jint*);
    void (*SetLongArrayRegion)(JNIEnv*, jlongArray,
                        jsize, jsize, const jlong*);
    void (*SetFloatArrayRegion)(JNIEnv*, jfloatArray,
                        jsize, jsize, const jfloat*);
    void (*SetDoubleArrayRegion)(JNIEnv*, jdoubleArray,
                        jsize, jsize, const jdouble*);

    jint (*RegisterNatives)(JNIEnv*, jclass, const JNINativeMethod*,
                        jint);
    jint (*UnregisterNatives)(JNIEnv*, jclass);
    jint (*MonitorEnter)(JNIEnv*, jobject);
    jint (*MonitorExit)(JNIEnv*, jobject);
    jint (*GetJavaVM)(JNIEnv*, JavaVM**);

    void (*GetStringRegion)(JNIEnv*, jstring, jsize, jsize, jchar*);
    void (*GetStringUTFRegion)(JNIEnv*, jstring, jsize, jsize, char*);

    void* (*GetPrimitiveArrayCritical)(JNIEnv*, jarray, jboolean*);
    void (*ReleasePrimitiveArrayCritical)(JNIEnv*, jarray, void*, jint);

    const jchar* (*GetStringCritical)(JNIEnv*, jstring, jboolean*);
    void (*ReleaseStringCritical)(JNIEnv*, jstring, const jchar*);

    jweak (*NewWeakGlobalRef)(JNIEnv*, jobject);
    void (*DeleteWeakGlobalRef)(JNIEnv*, jweak);

    jboolean (*ExceptionCheck)(JNIEnv*);

    jobject (*NewDirectByteBuffer)(JNIEnv*, void*, jlong);
    void* (*GetDirectBufferAddress)(JNIEnv*, jobject);
    jlong (*GetDirectBufferCapacity)(JNIEnv*, jobject);


    jobjectRefType (*GetObjectRefType)(JNIEnv*, jobject);
};







struct _JNIEnv {

    const struct JNINativeInterface* functions;
};





struct JNIInvokeInterface {
    void* reserved0;
    void* reserved1;
    void* reserved2;

    jint (*DestroyJavaVM)(JavaVM*);
    jint (*AttachCurrentThread)(JavaVM*, JNIEnv**, void*);
    jint (*DetachCurrentThread)(JavaVM*);
    jint (*GetEnv)(JavaVM*, void**, jint);
    jint (*AttachCurrentThreadAsDaemon)(JavaVM*, JNIEnv**, void*);
};




struct _JavaVM {
    const struct JNIInvokeInterface* functions;
};

struct _JavaVMAttachArgs {
    jint version;
    const char* name;
    jobject group;
};
typedef struct _JavaVMAttachArgs JavaVMAttachArgs;





typedef struct _JavaVMOption {
    const char* optionString;
    void* extraInfo;
} JavaVMOption;

typedef struct _JavaVMInitArgs {
    jint version;

    jint nOptions;
    JavaVMOption* options;
    jboolean ignoreUnrecognized;
} JavaVMInitArgs;
__attribute__ ((visibility ("default"))) jint JNI_OnLoad(JavaVM* vm, void* reserved);
__attribute__ ((visibility ("default"))) void JNI_OnUnload(JavaVM* vm, void* reserved);
