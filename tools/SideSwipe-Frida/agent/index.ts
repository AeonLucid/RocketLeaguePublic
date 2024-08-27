const libUE4 = 'libUE4.so';
const libEOSSDK = 'libEOSSDK.so';

// Rocket League SideSwipe
// Version 1.0 [458010]

// Find by searching for the string "FCurlHttpRequest::SetVerb()".
// Follow the xrefs to the vftable.
// Follow xref of the vftable to the constructor.
const UE4_FCurlHttpRequest_Constructor = 0x4FC3858;

// Find in the FCurlHttpRequest constructor.
// Look for the call to "sub_71CE8CC(*v1, 64LL, (unsigned __int8)word_7E38E10);"
// The constant "64" is the CURLOPT_SSL_VERIFYPEER option, which is an easy tell.
const UE4_FCurlHttpManager_bVerifyPeer = 0x7E38E10;

// Find by searching for the string "bDisableCertValidation".
const UE4_FLwsWebSocket_LwsCallback = 0x636DF38;

// Find by searching for the string "FCurlHttpRequest::SetVerb()".
// Follow the xrefs to the vftable.
// Follow xref of the vftable to the constructor.
const EOSSDK_FCurlHttpRequest_Constructor = 0xD67228;

// Find in the FCurlHttpRequest constructor.
// Look for the call to "sub_14B7EFC(*(a1 + 360), 64LL, word_161DFF0);"
// The constant "64" is the CURLOPT_SSL_VERIFYPEER option, which is an easy tell.
const EOSSDK_FCurlHttpManager_bVerifyPeer = 0x161DFF0;


Interceptor.attach(Module.findExportByName('libopenjdkjvm.so', 'JVM_NativeLoad')!, {
    onEnter: function(args) {
        const pEnv = args[0];
        const pJavaFilename = args[1];
        const pJavaLoader = args[2];
        const pJavaLibrarySearchPath = args[3];

        // Read library name
        const javaEnv = Java.vm.getEnv();
        const javaFilename = javaEnv.stringFromJni(pJavaFilename);

        this.fileName = javaFilename;
    },
    onLeave: function(retval) {
        if (retval.isNull()) {
            if (this.fileName.endsWith('/' + libUE4)) {
                loadedUE4();
            }
            
            if (this.fileName.endsWith('/' + libEOSSDK)) {
                loadedEOSSDK();
            }
        }
    }
});

function loadedUE4() {
    console.log('UE4 loaded');

    const baseAddress = Module.findBaseAddress(libUE4)!;
    
    // FCurlHttpRequest::FCurlHttpRequest()
    Interceptor.attach(baseAddress.add(UE4_FCurlHttpRequest_Constructor), {
        onEnter: function () {
            console.log('[UE4] FCurlHttpRequest::FCurlHttpRequest');

            // Disable SSL pinning.
            baseAddress.add(UE4_FCurlHttpManager_bVerifyPeer).writeU8(0);
        }
    });

    // FLwsWebSocket::LwsCallback(...)
    const LWS_CALLBACK_CLIENT_CONNECTION_ERROR = 1;
    const LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION = 58;

    const lwsCallbackPtr = baseAddress.add(UE4_FLwsWebSocket_LwsCallback);
    const lwsCallback = new NativeFunction(lwsCallbackPtr, 'int', ['pointer', 'pointer', 'int', 'pointer', 'int']);

    const ctxSetErrorPtr = Module.findExportByName(libUE4, 'X509_STORE_CTX_set_error')!;
    const ctxSetError = new NativeFunction(ctxSetErrorPtr, 'void', ['pointer', 'int']);

    Interceptor.replace(lwsCallbackPtr, new NativeCallback(function (pInstance, pUnknown, pReason, pData, pLength) {
        console.log(`[UE4] FLwsWebSocket::LwsCallback(${pInstance}, ${pReason}, ${pData}, ${pLength})`);

        if (pReason === LWS_CALLBACK_CLIENT_CONNECTION_ERROR) {
            console.log(`[UE4] FLwsWebSocket::LwsCallback error ${pData.readUtf8String()}`);
        }

        if (pReason !== LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION) {
            return lwsCallback(pInstance, pUnknown, pReason, pData, pLength);
        }

        console.log('[UE4] FLwsWebSocket::LwsCallback ssl unpinned');

        ctxSetError(pData, 0);
        return 0;
    }, 'int', ['pointer', 'pointer', 'int', 'pointer', 'int']));
}

function loadedEOSSDK() {
    console.log('EOSSDK loaded');

    const baseAddress = Module.findBaseAddress(libEOSSDK)!;
    
    // FCurlHttpRequest::FCurlHttpRequest()
    Interceptor.attach(baseAddress.add(EOSSDK_FCurlHttpRequest_Constructor), {
        onEnter: function () {
            console.log('[EOSSDK] FCurlHttpRequest::FCurlHttpRequest');

            // Disable SSL pinning.
            baseAddress.add(EOSSDK_FCurlHttpManager_bVerifyPeer).writeU8(0);
        }
    });
}