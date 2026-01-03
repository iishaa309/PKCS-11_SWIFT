//import Foundation
//
//class PKCS11Manager: ObservableObject {
//    @Published var log: String = ""
//    
//    func performTokenOperations(pin: String) async {
//        DispatchQueue.main.async {
//            self.log = ""
//            var rv: CK_RV = CKR_OK
//            let size = 2
//            let slotList = UnsafeMutablePointer<Int>.allocate(capacity: size)
//            var count: CK_ULONG = 0
//            let tokenPresent: CK_BBOOL = CK_BBOOL(CK_TRUE)
//            rv = C_Initialize(nil)
//            guard rv == CKR_OK else {
//                self.appendLog("❌ C_Initialize failed: \(rv)")
//                return
//            }
//            self.appendLog("✅ C_Initialize successful")
//            
//            rv = C_GetSlotList(tokenPresent, slotList, &count)
//            guard rv == CKR_OK, count > 0 else {
//                self.appendLog(
//                    "❌ C_GetSlotList failed or no slots found: \(rv)")
//                _ = C_Finalize(nil)
//                return
//            }
//            self.appendLog("✅ C_GetSlotList successful, slot count: \(count)")
//            
//            let slotID: CK_SLOT_ID = CK_SLOT_ID(slotList[0])
//            var hSession: CK_SESSION_HANDLE = 0
//            
//            rv = Int32(
//                C_OpenSession(
//                    slotID, CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil,
//                    nil, &hSession))
//            guard rv == CKR_OK else {
//                self.appendLog("❌ C_OpenSession failed: \(rv)")
//                _ = C_Finalize(nil)
//                return
//            }
//            self.appendLog("✅ C_OpenSession successful")
//            
//            var userPin = Array(pin.utf8)
//            rv = Int32(
//                C_Login(
//                    hSession, CK_USER_TYPE(CKU_USER), &userPin,
//                    CK_ULONG(userPin.count)))
//            guard rv == CKR_OK else {
//                self.appendLog("❌ Login failed: \(rv)")
//                _ = C_Finalize(nil)
//                return
//            }
//            self.appendLog("✅ Login successful")
//            
//            
//            var hKey: CK_OBJECT_HANDLE = 0
//            rv = C_DigestKey(hSession, hKey)
//            guard rv == CKR_OK else {
//                self.appendLog("❌ Digest failed: \(rv)")
//                _ = C_Finalize(nil)
//                return
//            }
//            self.appendLog("✅ Digest successful")
//            
//            //             --- Signing Operation ---
//            var pvt_class: CK_OBJECT_CLASS = CK_OBJECT_CLASS(CKO_PRIVATE_KEY)
//            var attr_pvt: [CK_ATTRIBUTE] = [
//                CK_ATTRIBUTE(
//                    type: CK_ATTRIBUTE_TYPE(CKA_CLASS),
//                    pValue: &pvt_class,
//                    ulValueLen: UInt(MemoryLayout<CK_OBJECT_CLASS>.size))
//            ]
//            var objectCount: CK_ULONG = 0
//            var hndd_pvt = [CK_OBJECT_HANDLE](repeating: 0, count: 10)
//            
//            rv = C_FindObjectsInit(hSession, &attr_pvt, 1)
//            guard rv == CKR_OK else {
//                self.appendLog("❌ C_FindObjectsInit failed: \(rv)")
//                _ = C_Finalize(nil)
//                return
//            }
//            
//            rv = C_FindObjects(hSession, &hndd_pvt, 10, &objectCount)
//            guard rv == CKR_OK else {
//                self.appendLog("❌ C_FindObjects failed: \(rv)")
//                _ = C_Finalize(nil)
//                return
//            }
//            
//            _ = C_FindObjectsFinal(hSession)
//            self.appendLog("🔑 Found \(objectCount) private key objects")
//            
//            // Sign
//            var mechanism = CK_MECHANISM(
//                mechanism: CK_MECHANISM_TYPE(CKM_SHA256_RSA_PKCS),
//                pParameter: nil,
//                ulParameterLen: 0)
//            rv = C_SignInit(hSession, &mechanism, hndd_pvt[0])
//            guard rv == CKR_OK else {
//                self.appendLog("❌ C_SignInit failed: \(rv)")
//                _ = C_Finalize(nil)
//                return
//            }
//            
//            let input = "****Plaintext to be signed*****"
//            var message = Array(input.utf8)
//            var sigLen: CK_ULONG = 256
//            let sigBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: 256)
//            defer { sigBuf.deallocate() }
//            
//            rv = Int32(
//                C_Sign(
//                    hSession, &message, CK_ULONG(message.count), sigBuf, &sigLen
//                ))
//            if rv == CKR_OK {
//                let signature = Data(bytes: sigBuf, count: Int(sigLen))
//                let hex = signature.map { String(format: "%02X", $0) }.joined()
//                self.appendLog("✍️ Signature: \(hex)")
//            } else {
//                self.appendLog("❌ C_Sign failed: \(rv)")
//            }
//            
//            _ = C_Logout(hSession)
//            _ = C_CloseSession(hSession)
//            _ = C_Finalize(nil)
//            self.appendLog("✅ Finalized PKCS#11 session")
//            
//            //            self.testInitialize()
//            self.testGetSlotList()
//            
//        }
//        
//    }
//    
//    // 👇 Move this outside of performTokenOperations
//    private func appendLog(_ text: String) {
//        DispatchQueue.main.async {
//            self.log += text + "\n"
//        }
//    }
//    //    func testInitialize() {
//    //        appendLog("=== Testing C_Initialize ===")
//    //
//    //        // Test 1: non-null pReserved
//    //        var args1 = CK_C_INITIALIZE_ARGS()
//    //        args1.pReserved = UnsafeMutableRawPointer(bitPattern: 1)
//    //        var rv = C_Initialize(&args1)
//    //        appendLog("Test 1: Initialize with non-null pReserved → \(rv)")
//    //
//    //        // Test 2: null pReserved
//    //        var args2 = CK_C_INITIALIZE_ARGS()
//    //        args2.pReserved = nil
//    //        rv = C_Initialize(&args2)
//    //        appendLog("Test 2: Initialize with null pReserved → \(rv)")
//    //
//    //        // Test 3: double initialize
//    //        _ = C_Finalize(nil)
//    //        rv = C_Initialize(nil)
//    //        _ = C_Initialize(nil)
//    //        appendLog("Test 3: Initialize twice → \(rv)")
//    //
//    //        // Test 4: CKF_LIBRARY_CANT_CREATE_OS_THREADS
//    //        var args4 = CK_C_INITIALIZE_ARGS()
//    //        args4.flags = CK_FLAGS(CKF_LIBRARY_CANT_CREATE_OS_THREADS)
//    //        rv = C_Initialize(&args4)
//    //        appendLog("Test 4: CKF_LIBRARY_CANT_CREATE_OS_THREADS → \(rv)")
//    //
//    //        // Test 5: after finalize
//    //        _ = C_Finalize(nil)
//    //        rv = C_Initialize(nil)
//    //        appendLog("Test 5: Initialize after finalize → \(rv)")
//    //
//    //        // Test 6: CKF_OS_LOCKING_OK
//    //        var args6 = CK_C_INITIALIZE_ARGS()
//    //        args6.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
//    //        rv = C_Initialize(&args6)
//    //        appendLog("Test 6: CKF_OS_LOCKING_OK → \(rv)")
//    //
//    //        _ = C_Finalize(nil)
//    //        appendLog("=== C_Initialize tests completed ===")
//    //    }
//  







import Foundation
import SwiftUI

// Missing PKCS#11 constants
let CKM_AES_KEY_WRAP_PAD: CK_MECHANISM_TYPE = 0x0000210A

class PKCS11Manager: ObservableObject {
    @Published var log: String = ""
    
    // Helper function to get error message
    func getErrorMessage(rv: CK_RV) -> String {
        switch UInt64(rv) {
        case UInt64(CKR_OK): return "CKR_OK: Function completed successfully"
        case UInt64(CKR_CANCEL): return "CKR_CANCEL: Function was cancelled"
        case UInt64(CKR_HOST_MEMORY): return "CKR_HOST_MEMORY: Insufficient memory"
        case UInt64(CKR_SLOT_ID_INVALID): return "CKR_SLOT_ID_INVALID: Invalid slot ID"
        case UInt64(CKR_GENERAL_ERROR): return "CKR_GENERAL_ERROR: General error"
        case UInt64(CKR_FUNCTION_FAILED): return "CKR_FUNCTION_FAILED: Function failed"
        case UInt64(CKR_ARGUMENTS_BAD): return "CKR_ARGUMENTS_BAD: Invalid arguments"
        case UInt64(CKR_NO_EVENT): return "CKR_NO_EVENT: No event occurred"
        case UInt64(CKR_NEED_TO_CREATE_THREADS): return "CKR_NEED_TO_CREATE_THREADS: Need to create threads"
        case UInt64(CKR_CANT_LOCK): return "CKR_CANT_LOCK: Cannot lock"
        case UInt64(CKR_ATTRIBUTE_READ_ONLY): return "CKR_ATTRIBUTE_READ_ONLY: Attribute is read-only"
        case UInt64(CKR_ATTRIBUTE_SENSITIVE): return "CKR_ATTRIBUTE_SENSITIVE: Attribute is sensitive"
        case UInt64(CKR_ATTRIBUTE_TYPE_INVALID): return "CKR_ATTRIBUTE_TYPE_INVALID: Invalid attribute type"
        case UInt64(CKR_ATTRIBUTE_VALUE_INVALID): return "CKR_ATTRIBUTE_VALUE_INVALID: Invalid attribute value"
        case UInt64(CKR_DATA_INVALID): return "CKR_DATA_INVALID: Invalid data"
        case UInt64(CKR_DATA_LEN_RANGE): return "CKR_DATA_LEN_RANGE: Data length out of range"
        case UInt64(CKR_DEVICE_ERROR): return "CKR_DEVICE_ERROR: Device error"
        case UInt64(CKR_DEVICE_MEMORY): return "CKR_DEVICE_MEMORY: Device memory error"
        case UInt64(CKR_DEVICE_REMOVED): return "CKR_DEVICE_REMOVED: Device removed"
        case UInt64(CKR_ENCRYPTED_DATA_INVALID): return "CKR_ENCRYPTED_DATA_INVALID: Invalid encrypted data"
        case UInt64(CKR_ENCRYPTED_DATA_LEN_RANGE): return "CKR_ENCRYPTED_DATA_LEN_RANGE: Encrypted data length out of range"
        case UInt64(CKR_FUNCTION_CANCELED): return "CKR_FUNCTION_CANCELED: Function canceled"
        case UInt64(CKR_FUNCTION_NOT_PARALLEL): return "CKR_FUNCTION_NOT_PARALLEL: Function not parallel"
        case UInt64(CKR_FUNCTION_NOT_SUPPORTED): return "CKR_FUNCTION_NOT_SUPPORTED: Function not supported"
        case UInt64(CKR_KEY_HANDLE_INVALID): return "CKR_KEY_HANDLE_INVALID: Invalid key handle"
        case UInt64(CKR_KEY_SIZE_RANGE): return "CKR_KEY_SIZE_RANGE: Key size out of range"
        case UInt64(CKR_KEY_TYPE_INCONSISTENT): return "CKR_KEY_TYPE_INCONSISTENT: Key type inconsistent"
        case UInt64(CKR_KEY_NOT_NEEDED): return "CKR_KEY_NOT_NEEDED: Key not needed"
        case UInt64(CKR_KEY_CHANGED): return "CKR_KEY_CHANGED: Key changed"
        case UInt64(CKR_KEY_NEEDED): return "CKR_KEY_NEEDED: Key needed"
        case UInt64(CKR_KEY_INDIGESTIBLE): return "CKR_KEY_INDIGESTIBLE: Key indigestible"
        case UInt64(CKR_KEY_FUNCTION_NOT_PERMITTED): return "CKR_KEY_FUNCTION_NOT_PERMITTED: Key function not permitted"
        case UInt64(CKR_KEY_NOT_WRAPPABLE): return "CKR_KEY_NOT_WRAPPABLE: Key not wrappable"
        case UInt64(CKR_KEY_UNEXTRACTABLE): return "CKR_KEY_UNEXTRACTABLE: Key unextractable"
        case UInt64(CKR_MECHANISM_INVALID): return "CKR_MECHANISM_INVALID: Invalid mechanism"
        case UInt64(CKR_MECHANISM_PARAM_INVALID): return "CKR_MECHANISM_PARAM_INVALID: Invalid mechanism parameter"
        case UInt64(CKR_OBJECT_HANDLE_INVALID): return "CKR_OBJECT_HANDLE_INVALID: Invalid object handle"
        case UInt64(CKR_OPERATION_ACTIVE): return "CKR_OPERATION_ACTIVE: Operation active"
        case UInt64(CKR_OPERATION_NOT_INITIALIZED): return "CKR_OPERATION_NOT_INITIALIZED: Operation not initialized"
        case UInt64(CKR_PIN_INCORRECT): return "CKR_PIN_INCORRECT: Incorrect PIN"
        case UInt64(CKR_PIN_INVALID): return "CKR_PIN_INVALID: Invalid PIN"
        case UInt64(CKR_PIN_LEN_RANGE): return "CKR_PIN_LEN_RANGE: PIN length out of range"
        case UInt64(CKR_PIN_EXPIRED): return "CKR_PIN_EXPIRED: PIN expired"
        case UInt64(CKR_PIN_LOCKED): return "CKR_PIN_LOCKED: PIN locked"
        case UInt64(CKR_SESSION_CLOSED): return "CKR_SESSION_CLOSED: Session closed"
        case UInt64(CKR_SESSION_COUNT): return "CKR_SESSION_COUNT: Session count error"
        case UInt64(CKR_SESSION_HANDLE_INVALID): return "CKR_SESSION_HANDLE_INVALID: Invalid session handle"
        case UInt64(CKR_SESSION_PARALLEL_NOT_SUPPORTED): return "CKR_SESSION_PARALLEL_NOT_SUPPORTED: Session parallel not supported"
        case UInt64(CKR_SESSION_READ_ONLY): return "CKR_SESSION_READ_ONLY: Session read-only"
        case UInt64(CKR_SESSION_EXISTS): return "CKR_SESSION_EXISTS: Session exists"
        case UInt64(CKR_SESSION_READ_ONLY_EXISTS): return "CKR_SESSION_READ_ONLY_EXISTS: Session read-only exists"
        case UInt64(CKR_SESSION_READ_WRITE_SO_EXISTS): return "CKR_SESSION_READ_WRITE_SO_EXISTS: Session read-write SO exists"
        case UInt64(CKR_SIGNATURE_INVALID): return "CKR_SIGNATURE_INVALID: Invalid signature"
        case UInt64(CKR_SIGNATURE_LEN_RANGE): return "CKR_SIGNATURE_LEN_RANGE: Signature length out of range"
        case UInt64(CKR_TEMPLATE_INCOMPLETE): return "CKR_TEMPLATE_INCOMPLETE: Template incomplete"
        case UInt64(CKR_TEMPLATE_INCONSISTENT): return "CKR_TEMPLATE_INCONSISTENT: Template inconsistent"
        case UInt64(CKR_TOKEN_NOT_PRESENT): return "CKR_TOKEN_NOT_PRESENT: Token not present"
        case UInt64(CKR_TOKEN_NOT_RECOGNIZED): return "CKR_TOKEN_NOT_RECOGNIZED: Token not recognized"
        case UInt64(CKR_TOKEN_WRITE_PROTECTED): return "CKR_TOKEN_WRITE_PROTECTED: Token write protected"
        case UInt64(CKR_UNWRAPPING_KEY_HANDLE_INVALID): return "CKR_UNWRAPPING_KEY_HANDLE_INVALID: Invalid unwrapping key handle"
        case UInt64(CKR_UNWRAPPING_KEY_SIZE_RANGE): return "CKR_UNWRAPPING_KEY_SIZE_RANGE: Unwrapping key size out of range"
        case UInt64(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT): return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: Unwrapping key type inconsistent"
        case UInt64(CKR_USER_ALREADY_LOGGED_IN): return "CKR_USER_ALREADY_LOGGED_IN: User already logged in"
        case UInt64(CKR_USER_NOT_LOGGED_IN): return "CKR_USER_NOT_LOGGED_IN: User not logged in"
        case UInt64(CKR_USER_PIN_NOT_INITIALIZED): return "CKR_USER_PIN_NOT_INITIALIZED: User PIN not initialized"
        case UInt64(CKR_USER_TYPE_INVALID): return "CKR_USER_TYPE_INVALID: Invalid user type"
        case UInt64(CKR_USER_ANOTHER_ALREADY_LOGGED_IN): return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN: Another user already logged in"
        case UInt64(CKR_USER_TOO_MANY_TYPES): return "CKR_USER_TOO_MANY_TYPES: Too many user types"
        case UInt64(CKR_WRAPPED_KEY_INVALID): return "CKR_WRAPPED_KEY_INVALID: Invalid wrapped key"
        case UInt64(CKR_WRAPPED_KEY_LEN_RANGE): return "CKR_WRAPPED_KEY_LEN_RANGE: Wrapped key length out of range"
        case UInt64(CKR_WRAPPING_KEY_HANDLE_INVALID): return "CKR_WRAPPING_KEY_HANDLE_INVALID: Invalid wrapping key handle"
        case UInt64(CKR_WRAPPING_KEY_SIZE_RANGE): return "CKR_WRAPPING_KEY_SIZE_RANGE: Wrapping key size out of range"
        case UInt64(CKR_WRAPPING_KEY_TYPE_INCONSISTENT): return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT: Wrapping key type inconsistent"
        case UInt64(CKR_RANDOM_SEED_NOT_SUPPORTED): return "CKR_RANDOM_SEED_NOT_SUPPORTED: Random seed not supported"
        case UInt64(CKR_RANDOM_NO_RNG): return "CKR_RANDOM_NO_RNG: No RNG available"
        case UInt64(CKR_DOMAIN_PARAMS_INVALID): return "CKR_DOMAIN_PARAMS_INVALID: Invalid domain parameters"
        case UInt64(CKR_BUFFER_TOO_SMALL): return "CKR_BUFFER_TOO_SMALL: Buffer too small"
        case UInt64(CKR_SAVED_STATE_INVALID): return "CKR_SAVED_STATE_INVALID: Invalid saved state"
        case UInt64(CKR_INFORMATION_SENSITIVE): return "CKR_INFORMATION_SENSITIVE: Information sensitive"
        case UInt64(CKR_STATE_UNSAVEABLE): return "CKR_STATE_UNSAVEABLE: State unsaveable"
        case UInt64(CKR_CRYPTOKI_NOT_INITIALIZED): return "CKR_CRYPTOKI_NOT_INITIALIZED: Cryptoki not initialized"
        case UInt64(CKR_CRYPTOKI_ALREADY_INITIALIZED): return "CKR_CRYPTOKI_ALREADY_INITIALIZED: Cryptoki already initialized"
        case UInt64(CKR_MUTEX_BAD): return "CKR_MUTEX_BAD: Mutex bad"
        case UInt64(CKR_MUTEX_NOT_LOCKED): return "CKR_MUTEX_NOT_LOCKED: Mutex not locked"
        default: return String(format: "Unknown error code: 0x%lx", rv)
        }
    }

    
    func performTokenOperations(pin: String) async {
        DispatchQueue.main.async {
            self.log = ""
            var rv: CK_RV = CK_RV(CKR_OK)
            var count: CK_ULONG = 0
            let tokenPresent: CK_BBOOL = CK_BBOOL(CK_TRUE)
            rv = C_Initialize(nil)
            guard rv == CKR_OK else {
                self.appendLog("❌ C_Initialize failed: \(rv)")
                return
            }
            self.appendLog("✅ C_Initialize successful")
            
            
            rv = C_GetSlotList(tokenPresent, nil, &count)
            guard rv == CKR_OK, count > 0 else {
                self.appendLog("❌ C_GetSlotList failed or no slots found: \(rv), count = \(count)")
                _ = C_Finalize(nil)
                return
            }
            self.appendLog("✅ C_GetSlotList successful — slot count: \(count)")
            
            let slots = UnsafeMutablePointer<CK_SLOT_ID>.allocate(capacity: Int(count))
            defer { slots.deallocate() }
            
            rv = C_GetSlotList(tokenPresent, slots, &count)
            guard rv == CKR_OK else {
                self.appendLog("❌ C_GetSlotList (second call) failed: \(rv)")
                _ = C_Finalize(nil)
                return
            }
            //            rv = C_GetSlotList(tokenPresent, slotList, &count)
            //            guard rv == CKR_OK, count > 0 else {
            //                self.appendLog(
            //                    "❌ C_GetSlotList failed or no slots found: \(rv)")
            //                _ = C_Finalize(nil)
            //                return
            //            }
            //            self.appendLog("✅ C_GetSlotList successful, slot count: \(count)")
            
            let slotID: CK_SLOT_ID = slots[0]
            var hSession: CK_SESSION_HANDLE = 0
            
            rv = C_OpenSession(
                slotID, CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil,
                nil, &hSession)
            guard rv == CKR_OK else {
                self.appendLog("❌ C_OpenSession failed: \(rv)")
                _ = C_Finalize(nil)
                return
            }
            self.appendLog("✅ C_OpenSession successful")
            
            var userPin = Array(pin.utf8)
            rv = C_Login(
                hSession, CK_USER_TYPE(CKU_USER), &userPin,
                CK_ULONG(userPin.count))
            guard rv == CKR_OK else {
                self.appendLog("❌ Login failed: \(rv)")
                _ = C_Finalize(nil)
                return
            }
            self.appendLog("✅ Login successful")
            
            
            var hKey: CK_OBJECT_HANDLE = 0
            rv = C_DigestKey(hSession, hKey)
            guard rv == CKR_OK else {
                self.appendLog("❌ Digest failed: \(rv)")
                _ = C_Finalize(nil)
                return
            }
            self.appendLog("✅ Digest successful")
            
            //             --- Signing Operation ---
            var pvt_class: CK_OBJECT_CLASS = CK_OBJECT_CLASS(CKO_PRIVATE_KEY)
            var attr_pvt: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(
                    type: CK_ATTRIBUTE_TYPE(CKA_CLASS),
                    pValue: &pvt_class,
                    ulValueLen: UInt(MemoryLayout<CK_OBJECT_CLASS>.size))
            ]
            var objectCount: CK_ULONG = 0
            var hndd_pvt = [CK_OBJECT_HANDLE](repeating: 0, count: 10)
            
            rv = C_FindObjectsInit(hSession, &attr_pvt, 1)
            guard rv == CKR_OK else {
                self.appendLog("❌ C_FindObjectsInit failed: \(rv)")
                _ = C_Finalize(nil)
                return
            }
            
            rv = C_FindObjects(hSession, &hndd_pvt, 10, &objectCount)
            guard rv == CKR_OK else {
                self.appendLog("❌ C_FindObjects failed: \(rv)")
                _ = C_Finalize(nil)
                return
            }
            
            _ = C_FindObjectsFinal(hSession)
            self.appendLog("🔑 Found \(objectCount) private key objects")
            
            // Sign
            var mechanism = CK_MECHANISM(
                mechanism: CK_MECHANISM_TYPE(CKM_SHA256_RSA_PKCS),
                pParameter: nil,
                ulParameterLen: 0)
            rv = C_SignInit(hSession, &mechanism, hndd_pvt[0])
            guard rv == CKR_OK else {
                self.appendLog("❌ C_SignInit failed: \(rv)")
                _ = C_Finalize(nil)
                return
            }
            
            let input = "****Plaintext to be signed*****"
            var message = Array(input.utf8)
            var sigLen: CK_ULONG = 256
            let sigBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: 256)
            defer { sigBuf.deallocate() }
            
            rv = C_Sign(
                    hSession, &message, CK_ULONG(message.count), sigBuf, &sigLen
                )
            if rv == CKR_OK {
                let signature = Data(bytes: sigBuf, count: Int(sigLen))
                let hex = signature.map { String(format: "%02X", $0) }.joined()
                self.appendLog("✍️ Signature: \(hex)")
            } else {
                self.appendLog("❌ C_Sign failed: \(rv)")
            }
            
            _ = C_Logout(hSession)
            _ = C_CloseSession(hSession)
            _ = C_Finalize(nil)
            self.appendLog("✅ Finalized PKCS#11 session")
            
            self.testInitialize()
            self.testGetSlotList()
            self.testOpenSession()
            self.testLogin()
            self.testLogout()
            self.testCloseSession()
            self.testCloseAllSessions()
            self.testGetSessionInfo()
            self.testGenerateKeyPair()
            self.testSign()
            self.testEncrypt()
            self.testDigestInit()
            self.testDigest()
            self.testSeedRandom()
            self.testGenerateRandom()
            self.testGetSlotInfo()
            self.testGetTokenInfo()
            self.testFinalize()
            self.testGetFunctionList()
            self.testGetInfo()
            self.testSignInit()
            self.testEncryptInit()
            self.testDecryptInit()
            self.testGetOperationState()
            self.testSetOperationState()
            self.testSignUpdate()
            self.testSignFinal()
            self.testSignRecoverInit()
            self.testSignRecover()
            self.testDigestUpdate()
            self.testDigestKey()
            self.testDigestFinal()
            self.testWaitForSlotEvent()
            self.testGetMechanismList()
            self.testGetMechanismInfo()
            self.testInitToken()
            self.testInitPIN()
            self.testSetPIN()
            self.testCreateObject()
            self.testCopyObject()
            self.testDestroyObject()
            self.testGetObjectSize()
            self.testGetAttributeValue()
            self.testSetAttributeValue()
            self.testFindObjectsInit()
            self.testFindObjects()
            self.testFindObjectsFinal()
            self.testVerifyInit()
            self.testVerify()
            self.testDecrypt()
            self.testGenerateKey()
            self.testUnwrapKey()
            self.testDeriveKey()
            self.testDigestEncryptUpdate()
            self.testDecryptDigestUpdate()
            self.testSignEncryptUpdate()
            self.testDecryptVerifyUpdate()
        }
        
    }
    
    // 👇 Move this outside of performTokenOperations
    private func appendLog(_ text: String) {
        DispatchQueue.main.async {
            self.log += text + "\n"
        }
    }
    func testInitialize() {
        appendLog("=== Testing C_Initialize ===")
        
        // Test 1: non-null pReserved
        var args1 = CK_C_INITIALIZE_ARGS()
        args1.pReserved = UnsafeMutableRawPointer(bitPattern: 1)
        var rv = C_Initialize(&args1)
        appendLog("Test 1: Initialize with non-null pReserved → \(rv)")
        
        // Test 2: null pReserved
        var args2 = CK_C_INITIALIZE_ARGS()
        args2.pReserved = nil
        rv = C_Initialize(&args2)
        appendLog("Test 2: Initialize with null pReserved → \(rv)")
        
        // Test 3: double initialize
        _ = C_Finalize(nil)
        rv = C_Initialize(nil)
        _ = C_Initialize(nil)
        appendLog("Test 3: Initialize twice → \(rv)")
        
        // Test 4: CKF_LIBRARY_CANT_CREATE_OS_THREADS
        var args4 = CK_C_INITIALIZE_ARGS()
        args4.flags = CK_FLAGS(CKF_LIBRARY_CANT_CREATE_OS_THREADS)
        rv = C_Initialize(&args4)
        appendLog("Test 4: CKF_LIBRARY_CANT_CREATE_OS_THREADS → \(rv)")
        
        // Test 5: after finalize
        _ = C_Finalize(nil)
        rv = C_Initialize(nil)
        appendLog("Test 5: Initialize after finalize → \(rv)")
        
        // Test 6: CKF_OS_LOCKING_OK
        var args6 = CK_C_INITIALIZE_ARGS()
        args6.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
        rv = C_Initialize(&args6)
        appendLog("Test 6: CKF_OS_LOCKING_OK → \(rv)")
        
        _ = C_Finalize(nil)
        appendLog("=== C_Initialize tests completed ===")
    }
    
    
    func resetTestState() {
        let rv = C_Finalize(nil)
        appendLog("C_Finalize → \(rv)")
    }
//        private func getSlotList(tokenPresent: Bool = true) -> [CK_SLOT_ID]? {
//            var slotCount: CK_ULONG = 0
//            var rv = C_GetSlotList(CK_BBOOL(tokenPresent ? CK_TRUE : CK_FALSE), nil, &slotCount)
//            appendLog("getSlotList() → First call (count) rv=\(rv), count=\(slotCount)")
//    
//            guard rv == CKR_OK, slotCount > 0 else {
//                appendLog("❌ No slots available or C_GetSlotList failed.")
//                return nil
//            }
//    
//            let slots = UnsafeMutablePointer<CK_SLOT_ID>.allocate(capacity: Int(slotCount))
//            defer { slots.deallocate() }
//    
//            rv = C_GetSlotList(CK_BBOOL(tokenPresent ? CK_TRUE : CK_FALSE), slots, &slotCount)
//            guard rv == CKR_OK else {
//                appendLog("❌ C_GetSlotList failed on second call: \(rv)")
//                return nil
//            }
//    
//            let result = Array(UnsafeBufferPointer(start: slots, count: Int(slotCount)))
//            appendLog("✅ Retrieved \(result.count) slot(s): \(result)")
//            return result
//        }
    
    
    // MARK: - Test: C_GetSlotList
    
    //    func testGetSlotList() {
    //        appendLog("\n=== Testing C_GetSlotList ===")
    //
    //        // Test 1: Query slot count only
    //        resetTestState()
    //        var rv = C_Initialize(nil)
    //        appendLog("C_Initialize → \(rv)")
    //
    //        var slotCount: CK_ULONG = 0
    //        rv = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &slotCount)
    //        appendLog("Test 1: Query slot count only → \(rv), slotCount = \(slotCount)")
    //
    //        // If no token present or count 0, retry with CK_FALSE
    //            if rv == CKR_TOKEN_NOT_PRESENT || slotCount == 0 {
    //                appendLog("⚠️ No tokens reported — retrying with CK_FALSE")
    //                rv = C_GetSlotList(CK_BBOOL(CK_FALSE), nil, &slotCount)
    //                appendLog("C_GetSlotList (CK_FALSE) → \(rv), slotCount = \(slotCount)")
    //            }
    //
    //        // ✅ Continue only if slots exist
    //        if rv != CKR_OK || slotCount == 0 {
    //            appendLog("⚠️ No slots available — skipping remaining GetSlotList tests.")
    //            _ = C_Finalize(nil)
    //            return
    //        }
    
    
    func testGetSlotList() {
        appendLog("\n=== 🧪 Testing C_GetSlotList ===")
        
        // Test 1: Token-present slots
        resetTestState()
        var rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        
        var slotCount: CK_ULONG = 0
        rv = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &slotCount)
        appendLog("Test 1 → rv=\(rv), slotCount=\(slotCount)")
        
        if rv == CKR_TOKEN_NOT_PRESENT || slotCount == 0 {
            appendLog("⚠️ No tokens — retrying in 1s...")
            Thread.sleep(forTimeInterval: 1.0)
            rv = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &slotCount)
            appendLog("Retry → rv=\(rv), slotCount=\(slotCount)")
        }
        
        if rv == CKR_OK && slotCount > 0 {
            appendLog("✅ Tokens available: \(slotCount)")
        } else {
            appendLog("❌ Still no tokens found — token may not be initialized.")
        }
        
        // Test 2: Query list of all slots (two-pass)
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        var count: CK_ULONG = 0
        rv = C_GetSlotList(CK_BBOOL(CK_FALSE), nil, &count)
        appendLog("Test 2a: First pass (count) → \(rv), count = \(count)")
        
        let slots = UnsafeMutablePointer<CK_SLOT_ID>.allocate(capacity: Int(count))
        defer { slots.deallocate() }
        rv = C_GetSlotList(CK_BBOOL(CK_FALSE), slots, &count)
        appendLog("Test 2b: Second pass (list) → \(rv), count = \(count)")
        
        // Test 3: Slots with tokens present
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        var presentCount: CK_ULONG = 0
        rv = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &presentCount)
        appendLog("Test 3a: First pass (token-present count) → \(rv), count = \(presentCount)")
        
        if presentCount > 0 {
            let presentSlots = UnsafeMutablePointer<CK_SLOT_ID>.allocate(capacity: Int(presentCount))
            defer { presentSlots.deallocate() }
            rv = C_GetSlotList(CK_BBOOL(CK_TRUE), presentSlots, &presentCount)
            appendLog("Test 3b: Token-present slots → \(rv), count = \(presentCount)")
        }
        
        // Test 4: Invalid buffer size
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        var smallCount: CK_ULONG = 0
        rv = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &smallCount)
        guard smallCount > 0 else {
            appendLog("No slots available for invalid-size test.")
            _ = C_Finalize(nil)
            return
        }
        appendLog("Expected slot count: \(smallCount)")
        
        let slotsList = UnsafeMutablePointer<CK_SLOT_ID>.allocate(capacity: Int(smallCount))
        defer { slotsList.deallocate() }
        var tooSmall: CK_ULONG = 1
        rv = C_GetSlotList(CK_BBOOL(CK_TRUE), slotsList, &tooSmall)
        appendLog("Test 4: Invalid buffer size → \(rv)")
        
        // Test 5: NULL count pointer
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        var tempSlots = [CK_SLOT_ID](repeating: 0, count: 10)
        rv = C_GetSlotList(CK_BBOOL(CK_TRUE), &tempSlots, nil)
        appendLog("Test 5: NULL count pointer → \(rv)")
        
        // Test 6: NULL slot list pointer with non-zero count
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        var nonZeroCount: CK_ULONG = 10
        rv = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &nonZeroCount)
        appendLog("Test 6: NULL slot list pointer with non-zero count → \(rv)")
        //
        // Test 7: Memory allocation failure simulation (disabled unless testing extreme cases)
        /*
         resetTestState()
         rv = C_Initialize(nil)
         appendLog("C_Initialize → \(rv)")
         var bigCount: CK_ULONG = 0
         rv = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &bigCount)
         appendLog("First pass (count) → \(rv)")
         var hugeCount: CK_ULONG = CK_ULONG.max / 2
         rv = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &hugeCount)
         appendLog("Test 7: Memory allocation failure simulation → \(rv)")
         */
        
        //        _ = C_Finalize(nil)
        //        appendLog("=== C_GetSlotList tests completed ===")
    }
    
    
    /// Helper: Get list of available PKCS#11 slot IDs
    func getSlotList() -> [CK_SLOT_ID]? {
        var slotCount: CK_ULONG = 0
        var rv = C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &slotCount)
        
        if rv != CKR_OK {
            appendLog("❌ C_GetSlotList (count query) failed → \(rv)")
            return nil
        }
        if slotCount == 0 {
            appendLog("⚠️ No slots available")
            return []
        }

        var slots = [CK_SLOT_ID](repeating: 0, count: Int(slotCount))
        rv = C_GetSlotList(CK_BBOOL(CK_TRUE), &slots, &slotCount)
        
        if rv != CKR_OK {
            appendLog("❌ C_GetSlotList (slot fetch) failed → \(rv)")
            return nil
        }
        appendLog("✅ Slots found: \(slots.map { "\($0)" }.joined(separator: ", "))")
        return Array(slots.prefix(Int(slotCount)))
    }

    
        func testOpenSession() {
            appendLog("\n=== Testing C_OpenSession ===")
    
            var rv: CK_RV = 0
            var hSession: CK_SESSION_HANDLE = 0
    
            // MARK: Test Case 1 - Random non-CDAC slot
            resetTestState()
            rv = C_Initialize(nil)
            appendLog("C_Initialize → \(rv)")
    
            if let slots = getSlotList(), !slots.isEmpty {
                let nonCDACSlot: CK_SLOT_ID = (slots[0] == 0) ? 1 : 0
    
                // ✅ FIXED: Wrap flags in CK_FLAGS()
                let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
                rv = C_OpenSession(nonCDACSlot, flags, nil, nil, &hSession)
    
                appendLog("Test 1: Open session with random slot ID other than CDAC Token slot → \(rv)")
            }

            resetTestState()
                _ = C_Initialize(nil)
                if let slots = getSlotList() {
                    let invalidSlotLow: CK_SLOT_ID = 0
                    let invalidSlotHigh: CK_SLOT_ID = CK_SLOT_ID(slots.count + 1)
                    let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)

                    rv = C_OpenSession(invalidSlotLow, flags, nil, nil, &hSession)
                    appendLog("Test 2.1: Open session with slot ID 0 → \(rv)")

                    rv = C_OpenSession(invalidSlotHigh, flags, nil, nil, &hSession)
                    appendLog("Test 2.2: Open session with slot ID greater than available → \(rv)")
                }

                // MARK: Test Case 3 - NULL session handle
                resetTestState()
                _ = C_Initialize(nil)
                if let slots = getSlotList() {
                    let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
                    rv = C_OpenSession(slots[0], flags, nil, nil, nil)
                    appendLog("Test 3: Open session with NULL session handle → \(rv)")
                }

                // MARK: Test Case 4 - Only CKF_RW_SESSION
                resetTestState()
                _ = C_Initialize(nil)
                if let slots = getSlotList() {
                    rv = C_OpenSession(slots[0], CK_FLAGS(CKF_RW_SESSION), nil, nil, &hSession)
                    appendLog("Test 4: Open session with only CKF_RW_SESSION flag → \(rv)")
                }

                // MARK: Test Case 5 - Only CKF_SERIAL_SESSION
                resetTestState()
                _ = C_Initialize(nil)
                if let slots = getSlotList() {
                    rv = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION), nil, nil, &hSession)
                    appendLog("Test 5: Open session with only CKF_SERIAL_SESSION flag → \(rv)")
                }

                // MARK: Test Case 6 - Duplicate flag combination
                resetTestState()
                _ = C_Initialize(nil)
                if let slots = getSlotList() {
                    rv = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_SERIAL_SESSION), nil, nil, &hSession)
                    appendLog("Test 6: Open session with duplicate flags → \(rv)")
                }

                // MARK: Test Case 7 - Flags = 0
                resetTestState()
                _ = C_Initialize(nil)
                if let slots = getSlotList() {
                    rv = C_OpenSession(slots[0], 0, nil, nil, &hSession)
                    appendLog("Test 7: Open session with flags = 0 → \(rv)")
                }

                // MARK: Test Case 8 - Without initialize
                resetTestState()
                rv = C_OpenSession(0, CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
                appendLog("Test 8: Open session without C_Initialize → \(rv)")

                // MARK: Test Case 9 - Without GetSlotList
                resetTestState()
                _ = C_Initialize(nil)
                rv = C_OpenSession(0, CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
                appendLog("Test 9: Open session without GetSlotList → \(rv)")

                // MARK: Test Case 10 - Repeatedly open 20 sessions
                resetTestState()
                _ = C_Initialize(nil)
                if let slots = getSlotList() {
                    var sessions = [CK_SESSION_HANDLE](repeating: 0, count: 20)
                    for i in 0..<20 {
                        rv = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &sessions[i])
                        appendLog("Test 10.\(i+1): Open session \(i+1)/20 → \(rv)")
                    }
                }

                // MARK: Test Case 11 - After 20 sessions
                resetTestState()
                _ = C_Initialize(nil)
                if let slots = getSlotList() {
                    var sessions = [CK_SESSION_HANDLE](repeating: 0, count: 20)
                    for i in 0..<20 {
                        _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &sessions[i])
                    }
                    rv = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
                    appendLog("Test 11: Open session after 20 sessions → \(rv)")
                }

                // MARK: Test Case 12 - Full lifecycle success
                resetTestState()
                _ = C_Initialize(nil)
                if let slots = getSlotList() {
                    rv = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
                    appendLog("Test 12.1: Open session success → \(rv)")

                    var sessionInfo = CK_SESSION_INFO()
                    rv = C_GetSessionInfo(hSession, &sessionInfo)
                    appendLog("Test 12.2: GetSessionInfo → \(rv)")
                    if rv == CKR_OK {
                        appendLog("Session flags: 0x\(String(sessionInfo.flags, radix: 16))")
                        appendLog("Session state: \(sessionInfo.state)")
                    }

                    rv = C_CloseSession(hSession)
                    appendLog("Test 12.5: Close session → \(rv)")
                }
            }
    
    func testFinalize() {
        appendLog("\n=== Testing C_Finalize ===")
        
        var rv: CK_RV = 0
        var slotCount: CK_ULONG = 0
        var slots: [CK_SLOT_ID] = []
        var hSession: CK_SESSION_HANDLE = 0
        
        // MARK: Test Case 1 - Finalize with non-NULL pointer
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        
        let reserved = UnsafeMutableRawPointer(bitPattern: 1)
        rv = C_Finalize(reserved)
        appendLog("Test 1: Finalize with non-NULL pointer → \(rv)")
        
        // MARK: Test Case 2 - Finalize when not initialized
        resetTestState()
        rv = C_Finalize(nil)
        appendLog("Test 2: Finalize when not initialized → \(rv)")
        
        // MARK: Test Case 3 - Finalize after closing all sessions
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        if let availableSlots = getSlotList(), !availableSlots.isEmpty {
            slots = availableSlots
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            rv = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            appendLog("C_OpenSession → \(rv)")
            rv = C_CloseAllSessions(slots[0])
            appendLog("C_CloseAllSessions → \(rv)")
        }
        rv = C_Finalize(nil)
        appendLog("Test 3: Finalize after closing all sessions → \(rv)")
        
        // MARK: Test Case 4 - Finalize after finalizing
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        rv = C_Finalize(nil)
        appendLog("First C_Finalize → \(rv)")
        rv = C_Finalize(nil)
        appendLog("Test 4: Finalize after finalizing → \(rv)")
        
        // MARK: Test Case 5 - Finalize with active sessions
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        if let availableSlots = getSlotList(), !availableSlots.isEmpty {
            slots = availableSlots
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            rv = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            appendLog("C_OpenSession → \(rv)")
        }
        rv = C_Finalize(nil)
        appendLog("Test 5: Finalize with active sessions → \(rv)")
        
        // MARK: Test Case 6 - Finalize after multiple initializations
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        rv = C_Finalize(nil)
        appendLog("First C_Finalize → \(rv)")
        rv = C_Initialize(nil)
        appendLog("Second C_Initialize → \(rv)")
        rv = C_Finalize(nil)
        appendLog("Test 6: Finalize after multiple initializations → \(rv)")
        
        // MARK: Test Case 8 - Finalize with multiple slots
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        if let availableSlots = getSlotList(), !availableSlots.isEmpty {
            slots = availableSlots
            for i in 0..<min(3, slots.count) {
                let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
                rv = C_OpenSession(slots[i], flags, nil, nil, &hSession)
                appendLog("C_OpenSession on slot \(slots[i]) → \(rv)")
            }
        }
        rv = C_Finalize(nil)
        appendLog("Test 8: Finalize with multiple slots → \(rv)")
        
        // MARK: Test Case 9 - Finalize after operations (simplified)
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        if let availableSlots = getSlotList(), !availableSlots.isEmpty {
            slots = availableSlots
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            rv = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            appendLog("C_OpenSession → \(rv)")
            
            // Sample login operation
            let pin = "123456"
            let pinData = pin.data(using: .utf8)!
            pinData.withUnsafeBytes { ptr in
                rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), UnsafeMutablePointer(mutating: ptr.bindMemory(to: CK_BYTE.self).baseAddress), CK_ULONG(pinData.count))
            }
            appendLog("C_Login → \(rv)")
        }
        rv = C_Finalize(nil)
        appendLog("Test 9: Finalize after operations → \(rv)")
        
        // MARK: Test Case 10 - Proper init/finalize
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        rv = C_Finalize(nil)
        appendLog("Test 10: Success case - proper initialization/finalization → \(rv)")
    }

    
    func testLogin() {
        appendLog("\n=== Testing C_Login ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            // Quietly check slots to avoid log spam, or just use getSlotList()
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Login with valid session ID
        if genericSetup() {
            var pinStr = Array(pin.utf8)
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            appendLog("Test 1: Login with valid session ID → \(rv)")
        }
        
        // Test Case 2: Login with invalid user type
        if genericSetup() {
            var pinStr = Array(pin.utf8)
            let rv = C_Login(hSession, 999, &pinStr, CK_ULONG(pinStr.count))
            appendLog("Test 2: Login with invalid user type → \(rv)")
        }
        
        // Test Case 3: Login with wrong PIN
        if genericSetup() {
            var wrongPin = Array("654321".utf8)
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), &wrongPin, CK_ULONG(wrongPin.count))
            appendLog("Test 3: Login with wrong PIN → \(rv)")
        }
        
        // Test Case 4: Login with nullptr PIN (Swift array nil isn't quite same, using empty or nil pointer if possible)
        if genericSetup() {
            // In Swift, we can pass nil to a pointer argument if it's optional, but C_Login expects UnsafeMutablePointer<CK_BYTE>! usually.
            // If the imported header defines it as optional, we can pass nil.
            // Assuming standard PKCS11 C_Login: CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
            // We'll try passing nil casted.
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), nil, 0)
            appendLog("Test 4: Login with nullptr PIN → \(rv)")
        }
        
        // Test Case 5: Login with invalid PIN length
        if genericSetup() {
            var shortPin = Array("123".utf8)
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), &shortPin, CK_ULONG(shortPin.count))
            appendLog("Test 5: Login with invalid PIN length → \(rv)")
        }
        
        // Test Case 7: Login with correct parameters (Success case)
        if genericSetup() {
            var pinStr = Array(pin.utf8)
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            appendLog("Test 7: Login with correct parameters → \(rv)")
        }
        
        // Test Case 8: Login multiple times
        if genericSetup() {
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            appendLog("Test 8: Login multiple times (should be CKR_USER_ALREADY_LOGGED_IN) → \(rv)")
        }
        
        // Test Case 9: Login with multiple sessions
        resetTestState()
        _ = C_Initialize(nil)
        if let slots = getSlotList(), !slots.isEmpty {
            var hSession1: CK_SESSION_HANDLE = 0
            var hSession2: CK_SESSION_HANDLE = 0
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession1)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession2)
            
            var pinStr = Array(pin.utf8)
            let rv1 = C_Login(hSession1, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            appendLog("Test 9.1: Login on first session → \(rv1)")
            
            let rv2 = C_Login(hSession2, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            appendLog("Test 9.2: Login on second session → \(rv2)")
        }
        
        // Test Case 10: Login after closing session
        if genericSetup() {
            _ = C_CloseSession(hSession)
            var pinStr = Array(pin.utf8)
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            appendLog("Test 10: Login after closing session (should be CKR_SESSION_HANDLE_INVALID) → \(rv)")
        }
        
        // Test Case 12: Login after finalize
        if genericSetup() {
            _ = C_Finalize(nil)
            var pinStr = Array(pin.utf8)
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            appendLog("Test 12: Login after finalize (should be CKR_CRYPTOKI_NOT_INITIALIZED) → \(rv)")
        }
    }

    func testGenerateKeyPair() {
        appendLog("\n=== Testing C_GenerateKeyPair ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Data setup
        let ckTrue: CK_BBOOL = CK_BBOOL(CK_TRUE)
        let ckFalse: CK_BBOOL = CK_BBOOL(CK_FALSE)
        let modulusBits: CK_ULONG = 2048
        
        let pubExpBytes: [CK_BYTE] = [0x01, 0x00, 0x01]
        let idBytes: [CK_BYTE] = [1]
        let subjectBytes: [CK_BYTE] = [0x55, 0x73, 0x65, 0x72, 0x31]
        
        // Need to keep these alive
        var ckTrueVal = ckTrue
        var ckFalseVal = ckFalse
        var modulusBitsVal = modulusBits
        var pubExpBytesVal = pubExpBytes
        var idBytesVal = idBytes
        var subjectBytesVal = subjectBytes
        
        // Create templates
        var pubTemplate: [CK_ATTRIBUTE] = [
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VERIFY), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_WRAP), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBitsVal, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &pubExpBytesVal, ulValueLen: CK_ULONG(pubExpBytesVal.count)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &idBytesVal, ulValueLen: CK_ULONG(idBytesVal.count)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
        ]
        
        var privTemplate: [CK_ATTRIBUTE] = [
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PRIVATE), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SENSITIVE), pValue: &ckFalseVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_EXTRACTABLE), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SIGN), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_UNWRAP), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &idBytesVal, ulValueLen: CK_ULONG(idBytesVal.count)),
            CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SUBJECT), pValue: &subjectBytesVal, ulValueLen: CK_ULONG(subjectBytesVal.count))
        ]
        
        if genericSetup() {
            var mech1 = CK_MECHANISM(mechanism: 0x999, pParameter: nil, ulParameterLen: 0)
            var pubKey1: CK_OBJECT_HANDLE = 0
            var privKey1: CK_OBJECT_HANDLE = 0
            
            let rv = C_GenerateKeyPair(hSession, &mech1, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &pubKey1, &privKey1)
            appendLog("Test 1: Generate key pair with invalid mechanism → \(rv)")
            
            var mech1_1 = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            let rv1_1 = C_GenerateKeyPair(hSession, &mech1_1, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &pubKey1, &privKey1)
            appendLog("Test 1.1: Generate key pair with valid mechanism → \(rv1_1)")
        }
        
        if genericSetup() {
             var mech2 = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
             var pubKey2: CK_OBJECT_HANDLE = 0
             var privKey2: CK_OBJECT_HANDLE = 0
             let rv = C_GenerateKeyPair(hSession, &mech2, nil, 0, nil, 0, &pubKey2, &privKey2)
             appendLog("Test 2: Generate key pair with nullptr public key template → \(rv)")
        }
    }

    func testSign() {
        appendLog("\n=== Testing C_Sign ===")

        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"

        func genericSetupAndKey() -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)? {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return nil }
            
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            
            // Helper to generate a temp key for signing
            var ckTrueVal: CK_BBOOL = CK_BBOOL(CK_TRUE)
            var modulusBitsVal: CK_ULONG = 2048
            var pubExpBytes: [CK_BYTE] = [0x01, 0x00, 0x01]
            var idBytes: [CK_BYTE] = [1]
            
            var pubT: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBitsVal, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &pubExpBytes, ulValueLen: 3),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &idBytes, ulValueLen: 1),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            var privT: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PRIVATE), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SENSITIVE), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SIGN), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_UNWRAP), pValue: &ckTrueVal, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &idBytes, ulValueLen: 1)
            ]
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            var pubK: CK_OBJECT_HANDLE = 0
            var privK: CK_OBJECT_HANDLE = 0
            _ = C_GenerateKeyPair(hSession, &mech, &pubT, CK_ULONG(pubT.count), &privT, CK_ULONG(privT.count), &pubK, &privK)
            return (pubK, privK)
        }
        
        let keys = genericSetupAndKey()
        let privKey = keys?.1 ?? 0
        
        var data: [CK_BYTE] = Array("test data".utf8)
        var signature = [CK_BYTE](repeating: 0, count: 256)
        var sigLen = CK_ULONG(signature.count)
        
        let rv1 = C_Sign(999, &data, CK_ULONG(data.count), &signature, &sigLen)
        appendLog("Test 1: Passing invalid session → \(rv1)")
        
        // Success case
        var signMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
        let rvInit = C_SignInit(hSession, &signMech, privKey)
        appendLog("C_SignInit → \(rvInit)")
        
        sigLen = CK_ULONG(signature.count)
        let rv13 = C_Sign(hSession, &data, CK_ULONG(data.count), &signature, &sigLen)
        appendLog("Test 13: Success case - satisfying all prerequisites → \(rv13)")
        if rv13 == CKR_OK {
             let hex = Data(signature.prefix(Int(sigLen))).map { String(format: "%02X", $0) }.joined()
             appendLog("Signature: \(hex)")
        }
    }

    func testEncrypt() {
        appendLog("\n=== Testing C_Encrypt ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"

        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        var data: [CK_BYTE] = Array("test data".utf8)
        var encrypted = [CK_BYTE](repeating: 0, count: 256)
        var encLen = CK_ULONG(encrypted.count)
        
        // Test Case 1: Encrypt with invalid session handle
        if genericSetup() {
             let rv = C_Encrypt(999, &data, CK_ULONG(data.count), &encrypted, &encLen)
             appendLog("Test 1: Encrypt with invalid session handle → \(rv)")
        }
        
        // Test Case 2: Encrypt with nullptr data
        if genericSetup() {
             let rv = C_Encrypt(hSession, nil, 0, &encrypted, &encLen)
             appendLog("Test 2: Encrypt with nullptr data → \(rv)")
        }
        
        // Test Case 3: Encrypt with nullptr encrypted buffer
        if genericSetup() {
             let rv = C_Encrypt(hSession, &data, CK_ULONG(data.count), nil, &encLen)
             appendLog("Test 3: Encrypt with nullptr encrypted buffer → \(rv)")
        }
    }

    func testDigestInit() {
        appendLog("\n=== Testing C_DigestInit ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"

        func genericSetupAndLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Passing valid session handle
        if genericSetupAndLogin() {
             var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
             let rv = C_DigestInit(hSession, &mech)
             appendLog("Test 1: Passing valid session handle → \(rv)")
        }
        
        // Test Case 2: Passing valid mechanism
        if genericSetupAndLogin() {
             var validMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
             let rv = C_DigestInit(hSession, &validMech)
             appendLog("Test 2: Passing valid mechanism → \(rv)")
        }
        
        // Test Case 3: Passing invalid session handle
        if genericSetupAndLogin() {
             var mech3 = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
             let rv = C_DigestInit(999, &mech3)
             appendLog("Test 3: Passing invalid session handle → \(rv)")
        }
        
        // Test Case 4: Passing invalid mechanism
        if genericSetupAndLogin() {
             var invalidMech = CK_MECHANISM(mechanism: 0xFFFFFFFF, pParameter: nil, ulParameterLen: 0)
             let rv = C_DigestInit(hSession, &invalidMech)
             appendLog("Test 4: Passing invalid mechanism → \(rv)")
        }
    }

    func testGetSessionInfo() {
        appendLog("\n=== Testing C_GetSessionInfo ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Get session info with random session ID
        if genericSetup() {
            var sessionInfo = CK_SESSION_INFO()
            let rv = C_GetSessionInfo(999, &sessionInfo)
            appendLog("Test 1: Get session info with random session ID → \(rv)")
        }
        
        // Test Case 2: Get session info with nullptr info parameter
        if genericSetup() {
            let rv = C_GetSessionInfo(hSession, nil)
            appendLog("Test 2: Get session info with nullptr info parameter → \(rv)")
        }
        
        // Test Case 3: Get session info with multiple sessions
        resetTestState()
        _ = C_Initialize(nil)
        if let slots = getSlotList(), !slots.isEmpty {
            var hSession1: CK_SESSION_HANDLE = 0
            var hSession2: CK_SESSION_HANDLE = 0
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession1)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession2)
            
            var sessionInfo = CK_SESSION_INFO()
            let rv1 = C_GetSessionInfo(hSession1, &sessionInfo)
            appendLog("Test 3.1: Get session info for first session → \(rv1)")
            let rv2 = C_GetSessionInfo(hSession2, &sessionInfo)
            appendLog("Test 3.2: Get session info for second session → \(rv2)")
        }
        
        // Test Case 4: Get session info after closing one session
        resetTestState()
        _ = C_Initialize(nil)
        if let slots = getSlotList(), !slots.isEmpty {
            var hSession1: CK_SESSION_HANDLE = 0
            var hSession2: CK_SESSION_HANDLE = 0
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession1)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession2)
            _ = C_CloseSession(hSession1)
            var sessionInfo = CK_SESSION_INFO()
            let rv = C_GetSessionInfo(hSession1, &sessionInfo)
            appendLog("Test 4: Get session info after closing session → \(rv)")
        }
        
        // Test Case 5: Get session info after finalize
        if genericSetup() {
            _ = C_Finalize(nil)
            var sessionInfo = CK_SESSION_INFO()
            let rv = C_GetSessionInfo(hSession, &sessionInfo)
            appendLog("Test 5: Get session info after finalize → \(rv)")
        }
        
        // Test Case 6: Success case - verify session info contents
        if genericSetup() {
            var sessionInfo = CK_SESSION_INFO()
            let rv = C_GetSessionInfo(hSession, &sessionInfo)
            if rv == CKR_OK {
                appendLog("Test 6: Session info contents:")
                appendLog("  Slot ID: \(sessionInfo.slotID)")
                appendLog("  State: \(sessionInfo.state)")
                appendLog("  Flags: 0x\(String(sessionInfo.flags, radix: 16))")
                appendLog("  ulDeviceError: \(sessionInfo.ulDeviceError)")
            }
            appendLog("Test 6: Success case → \(rv)")
        }
    }
    
    func testLogout() {
        appendLog("\n=== Testing C_Logout ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Logout with random session ID
        if genericSetup() {
            let rv = C_Logout(999)
            appendLog("Test 1: Logout with random session ID → \(rv)")
        }
        
        // Test Case 2: Multiple sessions logout
        resetTestState()
        _ = C_Initialize(nil)
        if let slots = getSlotList(), !slots.isEmpty {
            var hSession1: CK_SESSION_HANDLE = 0
            var hSession2: CK_SESSION_HANDLE = 0
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession1)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession2)
            
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession1, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            _ = C_Login(hSession2, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            
            let rv1 = C_Logout(hSession1)
            appendLog("Test 2.1: Logout from first session → \(rv1)")
        }
        
        // Test Case 3: Call logout function twice
        if genericSetup() {
            _ = C_Logout(hSession)
            let rv = C_Logout(hSession)
            appendLog("Test 3: Second logout (should be CKR_USER_NOT_LOGGED_IN) → \(rv)")
        }
        
        // Test Case 4: Logout after close all sessions
        if genericSetup() {
            if let slots = getSlotList(), !slots.isEmpty {
                _ = C_CloseAllSessions(slots[0])
            }
            let rv = C_Logout(hSession)
            appendLog("Test 4: Logout after close all sessions → \(rv)")
        }
        
        // Test Case 5: Logout after finalize
        if genericSetup() {
            _ = C_Finalize(nil)
            let rv = C_Logout(hSession)
            appendLog("Test 5: Logout after finalize → \(rv)")
        }
        
        // Test Case 6: Success case
        if genericSetup() {
            let rv = C_Logout(hSession)
            appendLog("Test 6: Success case - logout → \(rv)")
        }
    }
    
    func testCloseSession() {
        appendLog("\n=== Testing C_CloseSession ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Close random session handle that doesn't exist
        if genericSetup() {
            let rv = C_CloseSession(999)
            appendLog("Test 1: Close random session handle that doesn't exist → \(rv)")
        }
        
        // Test Case 2: Close session handle as '0'
        if genericSetup() {
            let rv = C_CloseSession(0)
            appendLog("Test 2: Close session handle as '0' → \(rv)")
        }
        
        // Test Case 3: Close valid session handle and verify
        if genericSetup() {
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            
            var sessionInfo = CK_SESSION_INFO()
            let rv1 = C_GetSessionInfo(hSession, &sessionInfo)
            appendLog("Test 3.1: Get session info before closing → \(rv1)")
            
            let rv2 = C_CloseSession(hSession)
            appendLog("Test 3.2: Close valid session handle → \(rv2)")
            
            let rv3 = C_GetSessionInfo(hSession, &sessionInfo)
            appendLog("Test 3.3: Get session info after closing → \(rv3)")
        }
        
        // Test Case 4: Close already closed session
        if genericSetup() {
            _ = C_CloseSession(hSession)
            let rv = C_CloseSession(hSession)
            appendLog("Test 4: Close already closed session → \(rv)")
        }
        
        // Test Case 5: Close session after finalize
        if genericSetup() {
            _ = C_Finalize(nil)
            let rv = C_CloseSession(hSession)
            appendLog("Test 5: Close session after finalize → \(rv)")
        }
    }
    
    func testCloseAllSessions() {
        appendLog("\n=== Testing C_CloseAllSessions ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Close all sessions with random slot ID
        if genericSetup() {
            let rv = C_CloseAllSessions(999)
            appendLog("Test 1: Close all sessions with random slot ID → \(rv)")
        }
        
        // Test Case 2: Call C_CloseAllSessions twice
        if genericSetup() {
            if let slots = getSlotList(), !slots.isEmpty {
                _ = C_CloseAllSessions(slots[0])
                let rv = C_CloseAllSessions(slots[0])
                appendLog("Test 2: Second C_CloseAllSessions → \(rv)")
            }
        }
        
        // Test Case 3: Call C_CloseAllSessions after finalize
        if genericSetup() {
            _ = C_Finalize(nil)
            let rv = C_CloseAllSessions(0)
            appendLog("Test 3: C_CloseAllSessions after finalize → \(rv)")
        }
        
        // Test Case 4: Success case - verify multiple sessions closed
        resetTestState()
        _ = C_Initialize(nil)
        if let slots = getSlotList(), !slots.isEmpty {
            var hSession1: CK_SESSION_HANDLE = 0
            var hSession2: CK_SESSION_HANDLE = 0
            var hSession3: CK_SESSION_HANDLE = 0
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession1)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession2)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession3)
            
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession1, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            
            let rv = C_CloseAllSessions(slots[0])
            appendLog("Test 4: Close all sessions → \(rv)")
            
            var sessionInfo = CK_SESSION_INFO()
            let rv1 = C_GetSessionInfo(hSession1, &sessionInfo)
            appendLog("Test 4.1: Session 1 after close all → \(rv1)")
            let rv2 = C_GetSessionInfo(hSession2, &sessionInfo)
            appendLog("Test 4.2: Session 2 after close all → \(rv2)")
            let rv3 = C_GetSessionInfo(hSession3, &sessionInfo)
            appendLog("Test 4.3: Session 3 after close all → \(rv3)")
        }
    }

    func testDigest() {
        appendLog("\n=== Testing C_Digest ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Success case - valid input, mechanism and data
        if genericSetup() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256), pParameter: nil, ulParameterLen: 0)
            _ = C_DigestInit(hSession, &mech)
            
            var data: [CK_BYTE] = Array("test data for digest".utf8)
            var digest = [CK_BYTE](repeating: 0, count: 32)
            var digestLen = CK_ULONG(digest.count)
            let rv = C_Digest(hSession, &data, CK_ULONG(data.count), &digest, &digestLen)
            appendLog("Test 1: Success case - valid input → \(rv)")
        }
        
        // Test Case 2: No C_DigestInit before C_Digest
        if genericSetup() {
            var data: [CK_BYTE] = Array("test data for digest".utf8)
            var digest = [CK_BYTE](repeating: 0, count: 32)
            var digestLen = CK_ULONG(digest.count)
            let rv = C_Digest(hSession, &data, CK_ULONG(data.count), &digest, &digestLen)
            appendLog("Test 2: No C_DigestInit before C_Digest → \(rv)")
        }
        
        // Test Case 3: nullptr data pointer
        if genericSetup() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256), pParameter: nil, ulParameterLen: 0)
            _ = C_DigestInit(hSession, &mech)
            
            var digest = [CK_BYTE](repeating: 0, count: 32)
            var digestLen = CK_ULONG(digest.count)
            let rv = C_Digest(hSession, nil, 0, &digest, &digestLen)
            appendLog("Test 3: nullptr data pointer → \(rv)")
        }
        
        // Test Case 4: Invalid Session Handle
        if genericSetup() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256), pParameter: nil, ulParameterLen: 0)
            _ = C_DigestInit(hSession, &mech)
            
            var data: [CK_BYTE] = Array("test data for digest".utf8)
            var digest = [CK_BYTE](repeating: 0, count: 32)
            var digestLen = CK_ULONG(digest.count)
            let rv = C_Digest(999, &data, CK_ULONG(data.count), &digest, &digestLen)
            appendLog("Test 4: Invalid Session Handle → \(rv)")
        }
        
        // Test Case 5: Digest buffer too small
        if genericSetup() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256), pParameter: nil, ulParameterLen: 0)
            _ = C_DigestInit(hSession, &mech)
            
            var data: [CK_BYTE] = Array("test data for digest".utf8)
            var smallDigest = [CK_BYTE](repeating: 0, count: 1)
            var smallDigestLen = CK_ULONG(smallDigest.count)
            let rv = C_Digest(hSession, &data, CK_ULONG(data.count), &smallDigest, &smallDigestLen)
            appendLog("Test 5: Digest buffer too small → \(rv)")
        }
    }
    
    func testSeedRandom() {
        appendLog("\n=== Testing C_SeedRandom ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Seed random with invalid session handle
        if genericSetup() {
            var seed: [CK_BYTE] = Array("random seed".utf8)
            let rv = C_SeedRandom(999, &seed, CK_ULONG(seed.count))
            appendLog("Test 1: Seed random with invalid session handle → \(rv)")
        }
        
        // Test Case 2: Seed random with nullptr seed
        if genericSetup() {
            let rv = C_SeedRandom(hSession, nil, 0)
            appendLog("Test 2: Seed random with nullptr seed → \(rv)")
        }
        
        // Test Case 3: Seed random with zero length
        if genericSetup() {
            var seed: [CK_BYTE] = Array("random seed".utf8)
            let rv = C_SeedRandom(hSession, &seed, 0)
            appendLog("Test 3: Seed random with zero length → \(rv)")
        }
        
        // Test Case 4: Success case
        if genericSetup() {
            var seed: [CK_BYTE] = Array("random seed".utf8)
            let rv = C_SeedRandom(hSession, &seed, CK_ULONG(seed.count))
            appendLog("Test 4: Success case → \(rv)")
        }
    }
    
    func testGenerateRandom() {
        appendLog("\n=== Testing C_GenerateRandom ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Generate random with invalid session handle
        if genericSetup() {
            var random = [CK_BYTE](repeating: 0, count: 32)
            let rv = C_GenerateRandom(999, &random, CK_ULONG(random.count))
            appendLog("Test 1: Generate random with invalid session handle → \(rv)")
        }
        
        // Test Case 2: Generate random with nullptr buffer
        if genericSetup() {
            let rv = C_GenerateRandom(hSession, nil, 32)
            appendLog("Test 2: Generate random with nullptr buffer → \(rv)")
        }
        
        // Test Case 3: Generate random with zero length
        if genericSetup() {
            var random = [CK_BYTE](repeating: 0, count: 32)
            let rv = C_GenerateRandom(hSession, &random, 0)
            appendLog("Test 3: Generate random with zero length → \(rv)")
        }
        
        // Test Case 4: Success case
        if genericSetup() {
            var random = [CK_BYTE](repeating: 0, count: 32)
            let rv = C_GenerateRandom(hSession, &random, CK_ULONG(random.count))
            appendLog("Test 4: Success case → \(rv)")
            if rv == CKR_OK {
                let hex = Data(random).map { String(format: "%02X", $0) }.joined()
                appendLog("Random: \(hex)")
            }
        }
    }
    
    func testGetSlotInfo() {
        appendLog("\n=== Testing C_GetSlotInfo ===")
        
        // Test Case 1: Valid slot ID
        resetTestState()
        _ = C_Initialize(nil)
        if let slots = getSlotList(), !slots.isEmpty {
            var slotInfo = CK_SLOT_INFO()
            let rv = C_GetSlotInfo(slots[0], &slotInfo)
            appendLog("Test 1: Valid slot ID → \(rv)")
            if rv == CKR_OK {
                let slotDesc = withUnsafeBytes(of: slotInfo.slotDescription) { rawPtr -> String in
                    let bytes = Array(rawPtr)
                    return String(bytes: bytes, encoding: .ascii)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                }
                appendLog("  Slot Description: \(slotDesc)")
            }
        }
        
        // Test Case 2: Invalid slot ID
        resetTestState()
        _ = C_Initialize(nil)
        var slotInfo2 = CK_SLOT_INFO()
        let rv2 = C_GetSlotInfo(999, &slotInfo2)
        appendLog("Test 2: Invalid slot ID → \(rv2)")
        
        // Test Case 3: nullptr pointer for slot info
        resetTestState()
        _ = C_Initialize(nil)
        if let slots = getSlotList(), !slots.isEmpty {
            let rv = C_GetSlotInfo(slots[0], nil)
            appendLog("Test 3: nullptr pointer for slot info → \(rv)")
        }
        
        // Test Case 4: After finalize
        resetTestState()
        _ = C_Initialize(nil)
        _ = C_Finalize(nil)
        var slotInfo4 = CK_SLOT_INFO()
        let rv4 = C_GetSlotInfo(0, &slotInfo4)
        appendLog("Test 4: After finalize → \(rv4)")
    }
    
    func testGetTokenInfo() {
        appendLog("\n=== Testing C_GetTokenInfo ===")
        
        // Test Case 1: Valid slot ID with present token
        resetTestState()
        _ = C_Initialize(nil)
        if let slots = getSlotList(), !slots.isEmpty {
            var tokenInfo = CK_TOKEN_INFO()
            let rv = C_GetTokenInfo(slots[0], &tokenInfo)
            appendLog("Test 1: Valid slot ID with present token → \(rv)")
            if rv == CKR_OK {
                let label = withUnsafeBytes(of: tokenInfo.label) { rawPtr -> String in
                    let bytes = Array(rawPtr)
                    return String(bytes: bytes, encoding: .ascii)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                }
                appendLog("  Token Label: \(label)")
            }
        }
        
        // Test Case 2: Invalid slot ID
        resetTestState()
        _ = C_Initialize(nil)
        var tokenInfo2 = CK_TOKEN_INFO()
        let rv2 = C_GetTokenInfo(999, &tokenInfo2)
        appendLog("Test 2: Invalid slot ID → \(rv2)")
        
        // Test Case 3: Null pointer passed
        resetTestState()
        _ = C_Initialize(nil)
        if let slots = getSlotList(), !slots.isEmpty {
            let rv = C_GetTokenInfo(slots[0], nil)
            appendLog("Test 3: Null pointer passed → \(rv)")
        }
        
        // Test Case 4: After finalize
        resetTestState()
        _ = C_Initialize(nil)
        _ = C_Finalize(nil)
        var tokenInfo4 = CK_TOKEN_INFO()
        let rv4 = C_GetTokenInfo(0, &tokenInfo4)
        appendLog("Test 4: After finalize → \(rv4)")
    }

    func testSignInit() {
        appendLog("\n=== Testing C_SignInit ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        var hPublicKey: CK_OBJECT_HANDLE = 0
        var hPrivateKey: CK_OBJECT_HANDLE = 0
        
        func genericSetupWithKey() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            
            // Generate RSA key pair for testing
            var modulusBits: CK_ULONG = 2048
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var id: [CK_BYTE] = [1]
            var ckTrue: CK_BBOOL = CK_BBOOL(CK_TRUE)
            var ckFalse: CK_BBOOL = CK_BBOOL(CK_FALSE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VERIFY), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PRIVATE), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SENSITIVE), pValue: &ckFalse, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SIGN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count))
            ]
            
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            let rv = C_GenerateKeyPair(hSession, &mech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey)
            return rv == CKR_OK
        }
        
        // Test Case 1: Passing invalid session
        if genericSetupWithKey() {
            var signMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_SignInit(999, &signMech, hPrivateKey)
            appendLog("Test 1: Passing invalid session → \(rv)")
        }
        
        // Test Case 2: Passing invalid key handle
        if genericSetupWithKey() {
            var signMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_SignInit(hSession, &signMech, 999)
            appendLog("Test 2: Passing invalid key handle → \(rv)")
        }
        
        // Test Case 3: Passing invalid mechanism
        if genericSetupWithKey() {
            var invalidMech = CK_MECHANISM(mechanism: 0x999, pParameter: nil, ulParameterLen: 0)
            let rv = C_SignInit(hSession, &invalidMech, hPrivateKey)
            appendLog("Test 3: Passing invalid mechanism → \(rv)")
        }
        
        // Test Case 4: Passing public key instead of private key
        if genericSetupWithKey() {
            var signMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_SignInit(hSession, &signMech, hPublicKey)
            appendLog("Test 4: Passing public key instead of private key → \(rv)")
        }
        
        // Test Case 5: Success case
        if genericSetupWithKey() {
            var signMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_SignInit(hSession, &signMech, hPrivateKey)
            appendLog("Test 5: Success case → \(rv)")
        }
    }

    func testEncryptInit() {
        appendLog("\n=== Testing C_EncryptInit ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        var hPublicKey: CK_OBJECT_HANDLE = 0
        var hPrivateKey: CK_OBJECT_HANDLE = 0
        
        func genericSetupWithKey() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            
            var modulusBits: CK_ULONG = 2048
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var id: [CK_BYTE] = [1]
            var ckTrue: CK_BBOOL = CK_BBOOL(CK_TRUE)
            var ckFalse: CK_BBOOL = CK_BBOOL(CK_FALSE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VERIFY), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PRIVATE), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SENSITIVE), pValue: &ckFalse, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SIGN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count))
            ]
            
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            let rv = C_GenerateKeyPair(hSession, &mech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey)
            return rv == CKR_OK
        }
        
        // Test Case 1: Success case - valid RSA mechanism and key
        if genericSetupWithKey() {
            var encryptMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_EncryptInit(hSession, &encryptMech, hPublicKey)
            appendLog("Test 1: Success case - valid RSA mechanism and key → \(rv)")
        }
        
        // Test Case 2: Invalid session handle
        if genericSetupWithKey() {
            var encryptMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_EncryptInit(999, &encryptMech, hPublicKey)
            appendLog("Test 2: Invalid session handle → \(rv)")
        }
        
        // Test Case 3: Invalid key handle
        if genericSetupWithKey() {
            var encryptMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_EncryptInit(hSession, &encryptMech, 999)
            appendLog("Test 3: Invalid key handle → \(rv)")
        }
        
        // Test Case 4: nullptr mechanism pointer
        if genericSetupWithKey() {
            let rv = C_EncryptInit(hSession, nil, hPublicKey)
            appendLog("Test 4: nullptr mechanism pointer → \(rv)")
        }
        
        // Test Case 5: Invalid mechanism type
        if genericSetupWithKey() {
            var invalidMech = CK_MECHANISM(mechanism: 0x999, pParameter: nil, ulParameterLen: 0)
            let rv = C_EncryptInit(hSession, &invalidMech, hPublicKey)
            appendLog("Test 5: Invalid mechanism type → \(rv)")
        }
    }

    func testDecryptInit() {
        appendLog("\n=== Testing C_DecryptInit ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        var hPublicKey: CK_OBJECT_HANDLE = 0
        var hPrivateKey: CK_OBJECT_HANDLE = 0
        
        func genericSetupWithKey() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            
            var modulusBits: CK_ULONG = 2048
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var id: [CK_BYTE] = [1]
            var ckTrue: CK_BBOOL = CK_BBOOL(CK_TRUE)
            var ckFalse: CK_BBOOL = CK_BBOOL(CK_FALSE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VERIFY), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PRIVATE), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SENSITIVE), pValue: &ckFalse, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SIGN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count))
            ]
            
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            let rv = C_GenerateKeyPair(hSession, &mech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey)
            return rv == CKR_OK
        }
        
        // Test Case 1: Success case - valid inputs
        if genericSetupWithKey() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_DecryptInit(hSession, &mech, hPrivateKey)
            appendLog("Test 1: Success case - valid inputs → \(rv)")
        }
        
        // Test Case 2: Invalid mechanism
        if genericSetupWithKey() {
            var invalidMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            let rv = C_DecryptInit(hSession, &invalidMech, hPrivateKey)
            appendLog("Test 2: Invalid mechanism → \(rv)")
        }
        
        // Test Case 3: Invalid key handle
        if genericSetupWithKey() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_DecryptInit(hSession, &mech, 999)
            appendLog("Test 3: Invalid key handle → \(rv)")
        }
        
        // Test Case 4: Invalid session handle
        if genericSetupWithKey() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_DecryptInit(999, &mech, hPrivateKey)
            appendLog("Test 4: Invalid session handle → \(rv)")
        }
        
        // Test Case 5: Use public key instead of private key for decryption
        if genericSetupWithKey() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_DecryptInit(hSession, &mech, hPublicKey)
            appendLog("Test 5: Use public key instead of private key → \(rv)")
        }
    }

    func testGetOperationState() {
        appendLog("\n=== Testing C_GetOperationState ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let digestMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256), pParameter: nil, ulParameterLen: 0)
        let pin = "123456"
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }

        func genericSetupWithLogin() -> Bool {
            if !genericSetup() { return false }
            var pinStr = Array(pin.utf8)
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return rv == CKR_OK
        }
        
        // Test Case 1: Valid digest operation initialized and updated
        if genericSetup() {
            var mutableMech = digestMech
            _ = C_DigestInit(hSession, &mutableMech)
            var data: [CK_BYTE] = Array("Test data".utf8)
            _ = C_DigestUpdate(hSession, &data, CK_ULONG(data.count))
            
            var stateLen: CK_ULONG = 0
            let rvSize = C_GetOperationState(hSession, nil, &stateLen)
            if rvSize == CKR_OK {
                var state = [CK_BYTE](repeating: 0, count: Int(stateLen))
                let rv = C_GetOperationState(hSession, &state, &stateLen)
                appendLog("Test 1: Valid digest operation → \(rv)")
            } else {
                appendLog("Test 1: Get state size failed → \(rvSize)")
            }
        }
        
        // Test Case 2: Query for state size only
        if genericSetup() {
            var mutableMech = digestMech
            _ = C_DigestInit(hSession, &mutableMech)
            var stateLen: CK_ULONG = 0
            let rv = C_GetOperationState(hSession, nil, &stateLen)
            appendLog("Test 2: Query for state size only → \(rv), Size: \(stateLen)")
        }
        
        // Test Case 3: State capture after encryption init
        if genericSetupWithLogin() {
            var encryptMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            
            // Need a public key for encryption init
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            var modulusBits: CK_ULONG = 2048
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var ckTrue = CK_BBOOL(CK_TRUE)
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count))
            ]
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            var genMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            if C_GenerateKeyPair(hSession, &genMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                _ = C_EncryptInit(hSession, &encryptMech, hPublicKey)
                var stateLen: CK_ULONG = 0
                let rv = C_GetOperationState(hSession, nil, &stateLen)
                appendLog("Test 3: Encryption state size → \(rv)")
            } else {
                appendLog("Test 3: Key generation failed")
            }
        }
        
        // Test Case 4: Session handle is invalid
        if genericSetup() {
            var stateLen: CK_ULONG = 0
            let rv = C_GetOperationState(999, nil, &stateLen)
            appendLog("Test 4: Invalid session handle → \(rv)")
        }
        
        // Test Case 5: No operation initialized
        if genericSetup() {
            var stateLen: CK_ULONG = 0
            let rv = C_GetOperationState(hSession, nil, &stateLen)
            appendLog("Test 5: No operation initialized → \(rv)")
        }
        
        // Test Case 6: After finalize
        if genericSetup() {
            var mutableMech = digestMech
            _ = C_DigestInit(hSession, &mutableMech)
            _ = C_Finalize(nil)
            var stateLen: CK_ULONG = 0
            let rv = C_GetOperationState(hSession, nil, &stateLen)
            appendLog("Test 6: After finalize → \(rv)")
        }
    }

    func testSetOperationState() {
        appendLog("\n=== Testing C_SetOperationState ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let digestMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256), pParameter: nil, ulParameterLen: 0)
        let pin = "123456"
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }

        func genericSetupWithLogin() -> Bool {
            if !genericSetup() { return false }
            var pinStr = Array(pin.utf8)
            let rv = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return rv == CKR_OK
        }
        
        // Test Case 1: Restore digest operation with no keys required
        if genericSetup() {
            var mutableMech = digestMech
            _ = C_DigestInit(hSession, &mutableMech)
            var data: [CK_BYTE] = Array("Test data".utf8)
            _ = C_DigestUpdate(hSession, &data, CK_ULONG(data.count))
            
            var stateLen: CK_ULONG = 0
            if C_GetOperationState(hSession, nil, &stateLen) == CKR_OK {
                var state = [CK_BYTE](repeating: 0, count: Int(stateLen))
                _ = C_GetOperationState(hSession, &state, &stateLen)
                
                // Close and reopen session
                _ = C_CloseSession(hSession)
                if let slots = getSlotList(), !slots.isEmpty {
                    let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
                    _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
                    
                    let rv = C_SetOperationState(hSession, &state, stateLen, 0, 0)
                    appendLog("Test 1: Restore digest state → \(rv)")
                }
            }
        }
        
        // Test Case 2: Restore operation with encryption key supplied
        if genericSetupWithLogin() {
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            var modulusBits: CK_ULONG = 2048
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var ckTrue = CK_BBOOL(CK_TRUE)
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count))
            ]
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            var genMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            if C_GenerateKeyPair(hSession, &genMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                var encryptMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
                _ = C_EncryptInit(hSession, &encryptMech, hPublicKey)
                
                var stateLen: CK_ULONG = 0
                if C_GetOperationState(hSession, nil, &stateLen) == CKR_OK {
                    var state = [CK_BYTE](repeating: 0, count: Int(stateLen))
                    _ = C_GetOperationState(hSession, &state, &stateLen)
                    
                    _ = C_CloseSession(hSession)
                    if let slots = getSlotList(), !slots.isEmpty {
                        let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
                        _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
                        
                        let rv = C_SetOperationState(hSession, &state, stateLen, hPublicKey, 0)
                        appendLog("Test 2: Restore encryption state → \(rv)")
                    }
                }
            }
        }
        
        // Test Case 3: Invalid session handle
        if genericSetup() {
            let rv = C_SetOperationState(999, nil, 0, 0, 0)
            appendLog("Test 3: Invalid session handle → \(rv)")
        }
        
        // Test Case 4: Invalid state data
        if genericSetup() {
            var invalidState = [CK_BYTE](repeating: 0xFF, count: 32)
            let rv = C_SetOperationState(hSession, &invalidState, 32, 0, 0)
            appendLog("Test 4: Invalid state data → \(rv)")
        }
        
        // Test Case 5: Missing required key
        if genericSetupWithLogin() {
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            var modulusBits: CK_ULONG = 2048
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var ckTrue = CK_BBOOL(CK_TRUE)
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count))
            ]
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            var genMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            if C_GenerateKeyPair(hSession, &genMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                var encryptMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
                _ = C_EncryptInit(hSession, &encryptMech, hPublicKey)
                
                var stateLen: CK_ULONG = 0
                if C_GetOperationState(hSession, nil, &stateLen) == CKR_OK {
                    var state = [CK_BYTE](repeating: 0, count: Int(stateLen))
                    _ = C_GetOperationState(hSession, &state, &stateLen)
                    
                    _ = C_CloseSession(hSession)
                    if let slots = getSlotList(), !slots.isEmpty {
                        let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
                        _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
                        
                        let rv = C_SetOperationState(hSession, &state, stateLen, 0, 0)
                        appendLog("Test 5: Missing required key → \(rv)")
                    }
                }
            }
        }
    }

    func testSignUpdate() {
        appendLog("\n=== Testing C_SignUpdate ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Sign update with invalid session handle
        if genericSetup() {
            var data: [CK_BYTE] = Array("test data".utf8)
            let rv = C_SignUpdate(999, &data, CK_ULONG(data.count))
            appendLog("Test 1: Sign update with invalid session → \(rv)")
        }
        
        // Test Case 2: Sign update with nullptr data
        if genericSetup() {
            let rv = C_SignUpdate(hSession, nil, 0)
            appendLog("Test 2: Sign update with nullptr data → \(rv)")
        }
    }

    func testSignFinal() {
        appendLog("\n=== Testing C_SignFinal ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Sign final with invalid session handle
        if genericSetup() {
            var signature = [CK_BYTE](repeating: 0, count: 256)
            var sigLen: CK_ULONG = CK_ULONG(signature.count)
            let rv = C_SignFinal(999, &signature, &sigLen)
            appendLog("Test 1: Sign final with invalid session → \(rv)")
        }
        
        // Test Case 2: Sign final with nullptr signature buffer
        if genericSetup() {
            var sigLen: CK_ULONG = 0
            let rv = C_SignFinal(hSession, nil, &sigLen)
            appendLog("Test 2: Sign final with nullptr signature buffer → \(rv)")
        }
    }

    func testSignRecoverInit() {
        appendLog("\n=== Testing C_SignRecoverInit ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Sign recover init with invalid session handle
        if genericSetup() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_SignRecoverInit(999, &mech, 0)
            appendLog("Test 1: Sign recover init with invalid session → \(rv)")
        }
        
        // Test Case 2: Sign recover init with nullptr mechanism
        if genericSetup() {
            let rv = C_SignRecoverInit(hSession, nil, 0)
            appendLog("Test 2: Sign recover init with nullptr mechanism → \(rv)")
        }
    }

    func testSignRecover() {
        appendLog("\n=== Testing C_SignRecover ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }
        
        // Test Case 1: Sign recover with invalid session handle
        if genericSetup() {
            var data: [CK_BYTE] = Array("test data".utf8)
            var signature = [CK_BYTE](repeating: 0, count: 256)
            var sigLen: CK_ULONG = CK_ULONG(signature.count)
            let rv = C_SignRecover(999, &data, CK_ULONG(data.count), &signature, &sigLen)
            appendLog("Test 1: Sign recover with invalid session → \(rv)")
        }
        
        // Test Case 2: Sign recover with nullptr data
        if genericSetup() {
            var signature = [CK_BYTE](repeating: 0, count: 256)
            var sigLen: CK_ULONG = CK_ULONG(signature.count)
            let rv = C_SignRecover(hSession, nil, 0, &signature, &sigLen)
            appendLog("Test 2: Sign recover with nullptr data → \(rv)")
        }
    }

    func testDigestUpdate() {
        appendLog("\n=== Testing C_DigestUpdate ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        let digestMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256), pParameter: nil, ulParameterLen: 0)
        
        func genericSetup() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            return true
        }

        func genericSetupWithLogin() -> Bool {
            if !genericSetup() { return false }
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Valid data
        if genericSetupWithLogin() {
            var mutableMech = digestMech
            _ = C_DigestInit(hSession, &mutableMech)
            var data: [CK_BYTE] = Array("test data".utf8)
            let rv = C_DigestUpdate(hSession, &data, CK_ULONG(data.count))
            appendLog("Test 1: Valid data → \(rv)")
        }
        
        // Test Case 2: Without Init
        if genericSetupWithLogin() {
            var data: [CK_BYTE] = Array("test data".utf8)
            let rv = C_DigestUpdate(hSession, &data, CK_ULONG(data.count))
            appendLog("Test 2: Without Init → \(rv)")
        }
        
        // Test Case 3: Invalid session handle
        if genericSetupWithLogin() {
            var data: [CK_BYTE] = Array("test data".utf8)
            let rv = C_DigestUpdate(999, &data, CK_ULONG(data.count))
            appendLog("Test 3: Invalid session handle → \(rv)")
        }
        
        // Test Case 4: nullptr data pointer
        if genericSetupWithLogin() {
            var mutableMech = digestMech
            _ = C_DigestInit(hSession, &mutableMech)
            let rv = C_DigestUpdate(hSession, nil, 10)
            appendLog("Test 4: nullptr data pointer → \(rv)")
        }
    }

    func testDigestKey() {
        appendLog("\n=== Testing C_DigestKey ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        let digestMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256), pParameter: nil, ulParameterLen: 0)
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Valid secret key
        if genericSetupWithLogin() {
            var genMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_AES_KEY_GEN), pParameter: nil, ulParameterLen: 0)
            var keyClass = CK_OBJECT_CLASS(CKO_SECRET_KEY)
            var keyType = CK_KEY_TYPE(CKK_AES)
            var trueValue = CK_BBOOL(CK_TRUE)
            var falseValue = CK_BBOOL(CK_FALSE)
            var ulValueLen: CK_ULONG = 32
            
            var keyTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &keyClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE), pValue: &keyType, ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE_LEN), pValue: &ulValueLen, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &falseValue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SENSITIVE), pValue: &falseValue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_EXTRACTABLE), pValue: &trueValue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hKey: CK_OBJECT_HANDLE = 0
            if C_GenerateKey(hSession, &genMech, &keyTemplate, CK_ULONG(keyTemplate.count), &hKey) == CKR_OK {
                var mutableDigestMech = digestMech
                _ = C_DigestInit(hSession, &mutableDigestMech)
                let rv = C_DigestKey(hSession, hKey)
                appendLog("Test 1: Valid secret key → \(rv)")
            } else {
                appendLog("Test 1: Key generation failed")
            }
        }
        
        // Test Case 2: Without Init
        if genericSetupWithLogin() {
            var hKey: CK_OBJECT_HANDLE = 0
            // Assuming we have a way to get a key, or just use a dummy handle
            let rv = C_DigestKey(hSession, 999)
            appendLog("Test 2: Without Init → \(rv)")
        }
    }

    func testDigestFinal() {
        appendLog("\n=== Testing C_DigestFinal ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        let digestMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA256), pParameter: nil, ulParameterLen: 0)
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            let flags = CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION)
            _ = C_OpenSession(slots[0], flags, nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Valid final
        if genericSetupWithLogin() {
            var mutableMech = digestMech
            _ = C_DigestInit(hSession, &mutableMech)
            var data: [CK_BYTE] = Array("test data".utf8)
            _ = C_DigestUpdate(hSession, &data, CK_ULONG(data.count))
            
            var digest = [CK_BYTE](repeating: 0, count: 32)
            var digestLen: CK_ULONG = CK_ULONG(digest.count)
            let rv = C_DigestFinal(hSession, &digest, &digestLen)
            appendLog("Test 1: Valid final → \(rv)")
        }
        
        // Test Case 2: Without Init
        if genericSetupWithLogin() {
            var digest = [CK_BYTE](repeating: 0, count: 32)
            var digestLen: CK_ULONG = CK_ULONG(digest.count)
            let rv = C_DigestFinal(hSession, &digest, &digestLen)
            appendLog("Test 2: Without Init → \(rv)")
        }
        
        // Test Case 3: Invalid session handle
        if genericSetupWithLogin() {
            var digest = [CK_BYTE](repeating: 0, count: 32)
            var digestLen: CK_ULONG = CK_ULONG(digest.count)
            let rv = C_DigestFinal(999, &digest, &digestLen)
            appendLog("Test 3: Invalid session handle → \(rv)")
        }
        
        // Test Case 4: nullptr digest buffer (to get length)
        if genericSetupWithLogin() {
            var mutableMech = digestMech
            _ = C_DigestInit(hSession, &mutableMech)
            var digestLen: CK_ULONG = 0
            let rv = C_DigestFinal(hSession, nil, &digestLen)
            appendLog("Test 4: nullptr digest buffer → \(rv), Size: \(digestLen)")
        }
    }

    func testWaitForSlotEvent() {
        appendLog("\n=== Testing C_WaitForSlotEvent ===")
        
        func genericSetup() {
            resetTestState()
            _ = C_Initialize(nil)
        }
        
        // Test Case 1: Non-blocking call
        genericSetup()
        var slotID: CK_SLOT_ID = 0
        let rv1 = C_WaitForSlotEvent(CK_FLAGS(CKF_DONT_BLOCK), &slotID, nil)
        appendLog("Test 1: Non-blocking call → \(rv1)")
        
        // Test Case 2: nullptr slot pointer
        genericSetup()
        let rv2 = C_WaitForSlotEvent(CK_FLAGS(CKF_DONT_BLOCK), nil, nil)
        appendLog("Test 2: nullptr slot pointer → \(rv2)")
        
        // Test Case 3: After finalize
        genericSetup()
        _ = C_Finalize(nil)
        let rv3 = C_WaitForSlotEvent(CK_FLAGS(CKF_DONT_BLOCK), &slotID, nil)
        appendLog("Test 3: After finalize → \(rv3)")
    }

    func testGetMechanismList() {
        appendLog("\n=== Testing C_GetMechanismList ===")
        
        func genericSetup() {
            resetTestState()
            _ = C_Initialize(nil)
        }
        
        // Test Case 1: Query count
        genericSetup()
        if let slots = getSlotList(), !slots.isEmpty {
            var count: CK_ULONG = 0
            let rv = C_GetMechanismList(slots[0], nil, &count)
            appendLog("Test 1: Query count → \(rv), Count: \(count)")
            
            // Test Case 2: Get list
            if rv == CKR_OK && count > 0 {
                var list = [CK_MECHANISM_TYPE](repeating: 0, count: Int(count))
                let rv2 = C_GetMechanismList(slots[0], &list, &count)
                appendLog("Test 2: Get list → \(rv2)")
            }
        }
        
        // Test Case 3: Invalid slot
        genericSetup()
        var count: CK_ULONG = 0
        let rv3 = C_GetMechanismList(999, nil, &count)
        appendLog("Test 3: Invalid slot → \(rv3)")
        
        // Test Case 4: nullptr count
        genericSetup()
        if let slots = getSlotList(), !slots.isEmpty {
            let rv4 = C_GetMechanismList(slots[0], nil, nil)
            appendLog("Test 4: nullptr count → \(rv4)")
        }
    }

    func testGetMechanismInfo() {
        appendLog("\n=== Testing C_GetMechanismInfo ===")
        
        func genericSetup() {
            resetTestState()
            _ = C_Initialize(nil)
        }
        
        // Test Case 1: Valid mechanism
        genericSetup()
        if let slots = getSlotList(), !slots.isEmpty {
            var info = CK_MECHANISM_INFO()
            let rv = C_GetMechanismInfo(slots[0], CK_MECHANISM_TYPE(CKM_SHA256), &info)
            appendLog("Test 1: Valid mechanism (SHA256) → \(rv)")
        }
        
        // Test Case 2: RSA mechanism
        genericSetup()
        if let slots = getSlotList(), !slots.isEmpty {
            var info = CK_MECHANISM_INFO()
            let rv = C_GetMechanismInfo(slots[0], CK_MECHANISM_TYPE(CKM_RSA_PKCS), &info)
            appendLog("Test 2: Valid mechanism (RSA_PKCS) → \(rv)")
        }
        
        // Test Case 3: Invalid slot
        genericSetup()
        var info = CK_MECHANISM_INFO()
        let rv3 = C_GetMechanismInfo(999, CK_MECHANISM_TYPE(CKM_SHA256), &info)
        appendLog("Test 3: Invalid slot → \(rv3)")
        
        // Test Case 4: Unsupported mechanism
        genericSetup()
        if let slots = getSlotList(), !slots.isEmpty {
            var info = CK_MECHANISM_INFO()
            let rv4 = C_GetMechanismInfo(slots[0], 0xFFFFFFFF, &info)
            appendLog("Test 4: Unsupported mechanism → \(rv4)")
        }
        
        // Test Case 5: nullptr info
        genericSetup()
        if let slots = getSlotList(), !slots.isEmpty {
            let rv5 = C_GetMechanismInfo(slots[0], CK_MECHANISM_TYPE(CKM_SHA256), nil)
            appendLog("Test 5: nullptr info → \(rv5)")
        }
    }

    func testInitToken() {
        appendLog("\n=== Testing C_InitToken ===")
        
        func genericSetup() {
            resetTestState()
            _ = C_Initialize(nil)
        }
        
        // Test Case 1: Invalid slot ID
        genericSetup()
        let soPin = Array("12345678".utf8)
        var label = [CK_UTF8CHAR](repeating: 32, count: 32)
        let rv1 = C_InitToken(999, UnsafeMutablePointer(mutating: soPin), CK_ULONG(soPin.count), &label)
        appendLog("Test 1: Invalid slot ID → \(rv1)")
        
        // Test Case 2: nullptr SO PIN (if not protected path)
        genericSetup()
        if let slots = getSlotList(), !slots.isEmpty {
            let rv2 = C_InitToken(slots[0], nil, 0, &label)
            appendLog("Test 2: nullptr SO PIN → \(rv2)")
        }
    }

    func testInitPIN() {
        appendLog("\n=== Testing C_InitPIN ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        
        func genericSetup() {
            resetTestState()
            _ = C_Initialize(nil)
        }
        
        // Test Case 1: Before Initialize
        resetTestState()
        let pin = Array("123456".utf8)
        let rv1 = C_InitPIN(0, UnsafeMutablePointer(mutating: pin), CK_ULONG(pin.count))
        appendLog("Test 1: Before Initialize → \(rv1)")
        
        // Test Case 2: Invalid session
        genericSetup()
        let rv2 = C_InitPIN(999, UnsafeMutablePointer(mutating: pin), CK_ULONG(pin.count))
        appendLog("Test 2: Invalid session → \(rv2)")
        
        // Test Case 3: Without SO login
        genericSetup()
        if let slots = getSlotList(), !slots.isEmpty {
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            let rv3 = C_InitPIN(hSession, UnsafeMutablePointer(mutating: pin), CK_ULONG(pin.count))
            appendLog("Test 3: Without SO login → \(rv3)")
        }
    }

    func testSetPIN() {
        appendLog("\n=== Testing C_SetPIN ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        
        func genericSetup() {
            resetTestState()
            _ = C_Initialize(nil)
        }
        
        // Test Case 1: Before Initialize
        resetTestState()
        let oldPin = Array("123456".utf8)
        let newPin = Array("654321".utf8)
        let rv1 = C_SetPIN(0, UnsafeMutablePointer(mutating: oldPin), CK_ULONG(oldPin.count), UnsafeMutablePointer(mutating: newPin), CK_ULONG(newPin.count))
        appendLog("Test 1: Before Initialize → \(rv1)")
        
        // Test Case 2: Invalid session
        genericSetup()
        let rv2 = C_SetPIN(999, UnsafeMutablePointer(mutating: oldPin), CK_ULONG(oldPin.count), UnsafeMutablePointer(mutating: newPin), CK_ULONG(newPin.count))
        appendLog("Test 2: Invalid session → \(rv2)")
        
        // Test Case 3: Public session (SetPIN requires login)
        genericSetup()
        if let slots = getSlotList(), !slots.isEmpty {
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            let rv3 = C_SetPIN(hSession, UnsafeMutablePointer(mutating: oldPin), CK_ULONG(oldPin.count), UnsafeMutablePointer(mutating: newPin), CK_ULONG(newPin.count))
            appendLog("Test 3: Public session → \(rv3)")
        }
    }

    func testCreateObject() {
        appendLog("\n=== Testing C_CreateObject ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Create data object
        if genericSetupWithLogin() {
            var objClass = CK_OBJECT_CLASS(CKO_DATA)
            var token = CK_BBOOL(CK_TRUE)
            var application = Array("My App".utf8)
            var value = Array("Sample Data".utf8)
            
            var template: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &objClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &token, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_APPLICATION), pValue: &application, ulValueLen: CK_ULONG(application.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE), pValue: &value, ulValueLen: CK_ULONG(value.count))
            ]
            
            var hObject: CK_OBJECT_HANDLE = 0
            let rv = C_CreateObject(hSession, &template, CK_ULONG(template.count), &hObject)
            appendLog("Test 1: Create data object → \(rv), Handle: \(hObject)")
        }
        
        // Test Case 2: Invalid attribute type
        if genericSetupWithLogin() {
            var objClass = CK_OBJECT_CLASS(CKO_DATA)
            var invalidVal = CK_ULONG(0)
            
            var template: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &objClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: 0xFFFFFFFF, pValue: &invalidVal, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size))
            ]
            
            var hObject: CK_OBJECT_HANDLE = 0
            let rv = C_CreateObject(hSession, &template, CK_ULONG(template.count), &hObject)
            appendLog("Test 2: Invalid attribute type → \(rv)")
        }
    }

    func testCopyObject() {
        appendLog("\n=== Testing C_CopyObject ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Copy data object
        if genericSetupWithLogin() {
            var objClass = CK_OBJECT_CLASS(CKO_DATA)
            var token = CK_BBOOL(CK_FALSE)
            var value = Array("Source Data".utf8)
            
            var template: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &objClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &token, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE), pValue: &value, ulValueLen: CK_ULONG(value.count))
            ]
            
            var hSource: CK_OBJECT_HANDLE = 0
            if C_CreateObject(hSession, &template, CK_ULONG(template.count), &hSource) == CKR_OK {
                var hCopied: CK_OBJECT_HANDLE = 0
                let rv = C_CopyObject(hSession, hSource, nil, 0, &hCopied)
                appendLog("Test 1: Copy data object → \(rv), Copied Handle: \(hCopied)")
            } else {
                appendLog("Test 1: Source object creation failed")
            }
        }
        
        // Test Case 2: Invalid object handle
        if genericSetupWithLogin() {
            var hCopied: CK_OBJECT_HANDLE = 0
            let rv = C_CopyObject(hSession, 999, nil, 0, &hCopied)
            appendLog("Test 2: Invalid object handle → \(rv)")
        }
    }

    func testDestroyObject() {
        appendLog("\n=== Testing C_DestroyObject ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Destroy data object
        if genericSetupWithLogin() {
            var objClass = CK_OBJECT_CLASS(CKO_DATA)
            var token = CK_BBOOL(CK_FALSE)
            var value = Array("Object to destroyed".utf8)
            
            var template: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &objClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &token, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE), pValue: &value, ulValueLen: CK_ULONG(value.count))
            ]
            
            var hObject: CK_OBJECT_HANDLE = 0
            if C_CreateObject(hSession, &template, CK_ULONG(template.count), &hObject) == CKR_OK {
                let rv = C_DestroyObject(hSession, hObject)
                appendLog("Test 1: Destroy data object → \(rv)")
            } else {
                appendLog("Test 1: Object creation failed")
            }
        }
        
        // Test Case 2: Invalid object handle
        if genericSetupWithLogin() {
            let rv = C_DestroyObject(hSession, 999)
            appendLog("Test 2: Invalid object handle → \(rv)")
        }
    }

    func testGetObjectSize() {
        appendLog("\n=== Testing C_GetObjectSize ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Get object size
        if genericSetupWithLogin() {
            var objClass = CK_OBJECT_CLASS(CKO_DATA)
            var token = CK_BBOOL(CK_FALSE)
            var value = Array("Object Size Test".utf8)
            
            var template: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &objClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &token, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE), pValue: &value, ulValueLen: CK_ULONG(value.count))
            ]
            
            var hObject: CK_OBJECT_HANDLE = 0
            if C_CreateObject(hSession, &template, CK_ULONG(template.count), &hObject) == CKR_OK {
                var size: CK_ULONG = 0
                let rv = C_GetObjectSize(hSession, hObject, &size)
                appendLog("Test 1: Get object size → \(rv), Size: \(size)")
            } else {
                appendLog("Test 1: Object creation failed")
            }
        }
        
        // Test Case 2: Invalid object handle
        if genericSetupWithLogin() {
            var size: CK_ULONG = 0
            let rv = C_GetObjectSize(hSession, 999, &size)
            appendLog("Test 2: Invalid object handle → \(rv)")
        }
    }

    func testGetAttributeValue() {
        appendLog("\n=== Testing C_GetAttributeValue ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Get attribute value
        if genericSetupWithLogin() {
            var objClass = CK_OBJECT_CLASS(CKO_DATA)
            var token = CK_BBOOL(CK_FALSE)
            var value = Array("Attribute Test".utf8)
            
            var template: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &objClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &token, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE), pValue: &value, ulValueLen: CK_ULONG(value.count))
            ]
            
            var hObject: CK_OBJECT_HANDLE = 0
            if C_CreateObject(hSession, &template, CK_ULONG(template.count), &hObject) == CKR_OK {
                var getTemplate: [CK_ATTRIBUTE] = [
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: nil, ulValueLen: 0),
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE), pValue: nil, ulValueLen: 0)
                ]
                
                var rv = C_GetAttributeValue(hSession, hObject, &getTemplate, 2)
                appendLog("Test 1: Get attribute sizes → \(rv)")
                
                if rv == CKR_OK {
                    getTemplate[0].pValue = malloc(Int(getTemplate[0].ulValueLen))
                    getTemplate[1].pValue = malloc(Int(getTemplate[1].ulValueLen))
                    
                    rv = C_GetAttributeValue(hSession, hObject, &getTemplate, 2)
                    appendLog("Test 1: Get attribute values → \(rv)")
                    
                    free(getTemplate[0].pValue)
                    free(getTemplate[1].pValue)
                }
            } else {
                appendLog("Test 1: Object creation failed")
            }
        }
        
        // Test Case 2: Invalid object handle
        if genericSetupWithLogin() {
            var getTemplate: [CK_ATTRIBUTE] = [CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: nil, ulValueLen: 0)]
            let rv = C_GetAttributeValue(hSession, 999, &getTemplate, 1)
            appendLog("Test 2: Invalid object handle → \(rv)")
        }
    }

    func testSetAttributeValue() {
        appendLog("\n=== Testing C_SetAttributeValue ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Set attribute value
        if genericSetupWithLogin() {
            var objClass = CK_OBJECT_CLASS(CKO_DATA)
            var token = CK_BBOOL(CK_FALSE)
            var value = Array("Object to update".utf8)
            
            var template: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &objClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &token, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE), pValue: &value, ulValueLen: CK_ULONG(value.count))
            ]
            
            var hObject: CK_OBJECT_HANDLE = 0
            if C_CreateObject(hSession, &template, CK_ULONG(template.count), &hObject) == CKR_OK {
                var newLabel = Array("Updated Label".utf8)
                var updateTemplate: [CK_ATTRIBUTE] = [
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_LABEL), pValue: &newLabel, ulValueLen: CK_ULONG(newLabel.count))
                ]
                
                let rv = C_SetAttributeValue(hSession, hObject, &updateTemplate, 1)
                appendLog("Test 1: Set attribute value → \(rv)")
            } else {
                appendLog("Test 1: Object creation failed")
            }
        }
        
        // Test Case 2: Invalid object handle
        if genericSetupWithLogin() {
            var newLabel = Array("Lost Label".utf8)
            var updateTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_LABEL), pValue: &newLabel, ulValueLen: CK_ULONG(newLabel.count))
            ]
            let rv = C_SetAttributeValue(hSession, 999, &updateTemplate, 1)
            appendLog("Test 2: Invalid object handle → \(rv)")
        }
    }

    func testFindObjectsInit() {
        appendLog("\n=== Testing C_FindObjectsInit ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Search for all objects
        if genericSetupWithLogin() {
            let rv = C_FindObjectsInit(hSession, nil, 0)
            appendLog("Test 1: Search for all objects → \(rv)")
            _ = C_FindObjectsFinal(hSession)
        }
        
        // Test Case 2: Search with template
        if genericSetupWithLogin() {
            var objClass = CK_OBJECT_CLASS(CKO_DATA)
            var template: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &objClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size))
            ]
            let rv = C_FindObjectsInit(hSession, &template, 1)
            appendLog("Test 2: Search with template → \(rv)")
            _ = C_FindObjectsFinal(hSession)
        }
        
        // Test Case 3: Invalid session
        if genericSetupWithLogin() {
            let rv = C_FindObjectsInit(999, nil, 0)
            appendLog("Test 3: Invalid session → \(rv)")
        }
    }

    func testFindObjects() {
        appendLog("\n=== Testing C_FindObjects ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Find objects
        if genericSetupWithLogin() {
            _ = C_FindObjectsInit(hSession, nil, 0)
            var handles = [CK_OBJECT_HANDLE](repeating: 0, count: 10)
            var count: CK_ULONG = 0
            let rv = C_FindObjects(hSession, &handles, 10, &count)
            appendLog("Test 1: Find objects → \(rv), Count: \(count)")
            _ = C_FindObjectsFinal(hSession)
        }
        
        // Test Case 2: Without Init
        if genericSetupWithLogin() {
            var handles = [CK_OBJECT_HANDLE](repeating: 0, count: 10)
            var count: CK_ULONG = 0
            let rv = C_FindObjects(hSession, &handles, 10, &count)
            appendLog("Test 2: Without Init → \(rv)")
        }
    }

    func testFindObjectsFinal() {
        appendLog("\n=== Testing C_FindObjectsFinal ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Finalize search
        if genericSetupWithLogin() {
            _ = C_FindObjectsInit(hSession, nil, 0)
            let rv = C_FindObjectsFinal(hSession)
            appendLog("Test 1: Finalize search → \(rv)")
        }
        
        // Test Case 2: Without Init
        if genericSetupWithLogin() {
            let rv = C_FindObjectsFinal(hSession)
            appendLog("Test 2: Without Init → \(rv)")
        }
    }

    func testVerifyInit() {
        appendLog("\n=== Testing C_VerifyInit ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Valid verify init
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            
            // Generate RSA key pair
            var keyGenMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            var modulusBits = CK_ULONG(2048)
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var id: [CK_BYTE] = [1]
            var ckTrue = CK_BBOOL(CK_TRUE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VERIFY), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SIGN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            
            if C_GenerateKeyPair(hSession, &keyGenMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                let rv = C_VerifyInit(hSession, &mech, hPublicKey)
                appendLog("Test 1: Valid verify init → \(rv)")
            } else {
                appendLog("Test 1: Key pair generation failed")
            }
        }
        
        // Test Case 2: Invalid session
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            let rv = C_VerifyInit(999, &mech, 0)
            appendLog("Test 2: Invalid session → \(rv)")
        }
    }

    func testVerify() {
        appendLog("\n=== Testing C_Verify ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Valid verify
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            
            // Generate RSA key pair
            var keyGenMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            var modulusBits = CK_ULONG(2048)
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var id: [CK_BYTE] = [1]
            var ckTrue = CK_BBOOL(CK_TRUE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VERIFY), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SIGN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            
            if C_GenerateKeyPair(hSession, &keyGenMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                var data = Array("Data to sign".utf8)
                var signature = [CK_BYTE](repeating: 0, count: 256)
                var sigLen = CK_ULONG(signature.count)
                
                _ = C_SignInit(hSession, &mech, hPrivateKey)
                if C_Sign(hSession, &data, CK_ULONG(data.count), &signature, &sigLen) == CKR_OK {
                    _ = C_VerifyInit(hSession, &mech, hPublicKey)
                    let rv = C_Verify(hSession, &data, CK_ULONG(data.count), &signature, sigLen)
                    appendLog("Test 1: Valid verify → \(rv)")
                } else {
                    appendLog("Test 1: Sign failed")
                }
            } else {
                appendLog("Test 1: Key pair generation failed")
            }
        }
    }

    func testDecrypt() {
        appendLog("\n=== Testing C_Decrypt ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Valid decrypt
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            
            // Generate RSA key pair
            var keyGenMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            var modulusBits = CK_ULONG(2048)
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var id: [CK_BYTE] = [1]
            var ckTrue = CK_BBOOL(CK_TRUE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ID), pValue: &id, ulValueLen: CK_ULONG(id.count)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            
            if C_GenerateKeyPair(hSession, &keyGenMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                var plaintext = Array("Secret message".utf8)
                var encrypted = [CK_BYTE](repeating: 0, count: 256)
                var encLen = CK_ULONG(encrypted.count)
                
                _ = C_EncryptInit(hSession, &mech, hPublicKey)
                if C_Encrypt(hSession, &plaintext, CK_ULONG(plaintext.count), &encrypted, &encLen) == CKR_OK {
                    var decrypted = [CK_BYTE](repeating: 0, count: 256)
                    var decLen = CK_ULONG(decrypted.count)
                    
                    _ = C_DecryptInit(hSession, &mech, hPrivateKey)
                    let rv = C_Decrypt(hSession, &encrypted, encLen, &decrypted, &decLen)
                    appendLog("Test 1: Valid decrypt → \(rv)")
                    
                    if rv == CKR_OK {
                        let result = String(decoding: decrypted.prefix(Int(decLen)), as: UTF8.self)
                        appendLog("Decrypted: \(result)")
                    }
                } else {
                    appendLog("Test 1: Encrypt failed")
                }
            } else {
                appendLog("Test 1: Key pair generation failed")
            }
        }
    }

    func testGenerateKey() {
        appendLog("\n=== Testing C_GenerateKey ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Generate AES key
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_AES_KEY_GEN), pParameter: nil, ulParameterLen: 0)
            
            var keyClass = CK_OBJECT_CLASS(CKO_SECRET_KEY)
            var keyType = CK_KEY_TYPE(CKK_AES)
            var valueLen = CK_ULONG(32) // AES-256
            var token = CK_BBOOL(CK_FALSE)
            var encrypt = CK_BBOOL(CK_TRUE)
            var decrypt = CK_BBOOL(CK_TRUE)
            
            var template: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &keyClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE), pValue: &keyType, ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE_LEN), pValue: &valueLen, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_TOKEN), pValue: &token, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &encrypt, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &decrypt, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hKey: CK_OBJECT_HANDLE = 0
            let rv = C_GenerateKey(hSession, &mech, &template, CK_ULONG(template.count), &hKey)
            appendLog("Test 1: Generate AES key → \(rv), Handle: \(hKey)")
        }
    }

    func testUnwrapKey() {
        appendLog("\n=== Testing C_UnwrapKey ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Unwrap key
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_AES_KEY_WRAP_PAD), pParameter: nil, ulParameterLen: 0)
            
            // Generate wrapping key
            var wrapKeyType = CK_KEY_TYPE(CKK_AES)
            var wrapKeyLen = CK_ULONG(32)
            var wrapTrue = CK_BBOOL(CK_TRUE)
            var wrapTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE), pValue: &wrapKeyType, ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE_LEN), pValue: &wrapKeyLen, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_WRAP), pValue: &wrapTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hWrappingKey: CK_OBJECT_HANDLE = 0
            var genMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_AES_KEY_GEN), pParameter: nil, ulParameterLen: 0)
            if C_GenerateKey(hSession, &genMech, &wrapTemplate, CK_ULONG(wrapTemplate.count), &hWrappingKey) == CKR_OK {
                var wrappedKeyData: [CK_BYTE] = [0xDE, 0xAD, 0xBE, 0xEF]
                var unwrapClass = CK_OBJECT_CLASS(CKO_SECRET_KEY)
                var unwrapType = CK_KEY_TYPE(CKK_AES)
                var unwrapTrue = CK_BBOOL(CK_TRUE)
                var unwrapTemplate: [CK_ATTRIBUTE] = [
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &unwrapClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE), pValue: &unwrapType, ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)),
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &unwrapTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
                ]
                
                var hUnwrappedKey: CK_OBJECT_HANDLE = 0
                let rv = C_UnwrapKey(hSession, &mech, hWrappingKey, &wrappedKeyData, CK_ULONG(wrappedKeyData.count), &unwrapTemplate, CK_ULONG(unwrapTemplate.count), &hUnwrappedKey)
                appendLog("Test 1: Unwrap key → \(rv)")
            } else {
                appendLog("Test 1: Wrapping key generation failed")
            }
        }
    }

    func testDeriveKey() {
        appendLog("\n=== Testing C_DeriveKey ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Derive key
        if genericSetupWithLogin() {
            var keyClass = CK_OBJECT_CLASS(CKO_SECRET_KEY)
            var keyType = CK_KEY_TYPE(CKK_AES)
            var keyLen = CK_ULONG(32)
            var deriveTrue = CK_BBOOL(CK_TRUE)
            
            var baseTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &keyClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE), pValue: &keyType, ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VALUE_LEN), pValue: &keyLen, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DERIVE), pValue: &deriveTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hBaseKey: CK_OBJECT_HANDLE = 0
            var genMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_AES_KEY_GEN), pParameter: nil, ulParameterLen: 0)
            if C_GenerateKey(hSession, &genMech, &baseTemplate, CK_ULONG(baseTemplate.count), &hBaseKey) == CKR_OK {
                var deriveMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_ECDH1_DERIVE), pParameter: nil, ulParameterLen: 0)
                var derivedTrue = CK_BBOOL(CK_TRUE)
                var derivedTemplate: [CK_ATTRIBUTE] = [
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS), pValue: &keyClass, ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size)),
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_KEY_TYPE), pValue: &keyType, ulValueLen: CK_ULONG(MemoryLayout<CK_KEY_TYPE>.size)),
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &derivedTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                    CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &derivedTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
                ]
                
                var hDerivedKey: CK_OBJECT_HANDLE = 0
                let rv = C_DeriveKey(hSession, &deriveMech, hBaseKey, &derivedTemplate, CK_ULONG(derivedTemplate.count), &hDerivedKey)
                appendLog("Test 1: Derive key → \(rv)")
            } else {
                appendLog("Test 1: Base key generation failed")
            }
        }
    }

    func testDigestEncryptUpdate() {
        appendLog("\n=== Testing C_DigestEncryptUpdate ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Digest and Encrypt update
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA1_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            
            // Generate RSA key pair
            var keyGenMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            var modulusBits = CK_ULONG(2048)
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var ckTrue = CK_BBOOL(CK_TRUE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            
            if C_GenerateKeyPair(hSession, &keyGenMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                _ = C_DigestInit(hSession, &mech)
                _ = C_EncryptInit(hSession, &mech, hPublicKey)
                
                var data = Array("Digest and Encrypt this data".utf8)
                var encrypted = [CK_BYTE](repeating: 0, count: 512)
                var encLen = CK_ULONG(encrypted.count)
                
                let rv = C_DigestEncryptUpdate(hSession, &data, CK_ULONG(data.count), &encrypted, &encLen)
                appendLog("Test 1: Digest and Encrypt update → \(rv)")
            } else {
                appendLog("Test 1: Key pair generation failed")
            }
        }
    }

    func testDecryptDigestUpdate() {
        appendLog("\n=== Testing C_DecryptDigestUpdate ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Decrypt and Digest update
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_SHA1_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            
            // Generate RSA key pair
            var keyGenMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            var modulusBits = CK_ULONG(2048)
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var ckTrue = CK_BBOOL(CK_TRUE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            
            if C_GenerateKeyPair(hSession, &keyGenMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                _ = C_DecryptInit(hSession, &mech, hPrivateKey)
                _ = C_DigestInit(hSession, &mech)
                
                var encryptedData: [CK_BYTE] = [0x01, 0x02, 0x03, 0x04]
                var output = [CK_BYTE](repeating: 0, count: 512)
                var outputLen = CK_ULONG(output.count)
                
                let rv = C_DecryptDigestUpdate(hSession, &encryptedData, CK_ULONG(encryptedData.count), &output, &outputLen)
                appendLog("Test 1: Decrypt and Digest update → \(rv)")
            } else {
                appendLog("Test 1: Key pair generation failed")
            }
        }
    }

    func testSignEncryptUpdate() {
        appendLog("\n=== Testing C_SignEncryptUpdate ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Sign and Encrypt update
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            
            // Generate RSA key pair
            var keyGenMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            var modulusBits = CK_ULONG(2048)
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var ckTrue = CK_BBOOL(CK_TRUE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_ENCRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_SIGN), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            
            if C_GenerateKeyPair(hSession, &keyGenMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                _ = C_SignInit(hSession, &mech, hPrivateKey)
                _ = C_EncryptInit(hSession, &mech, hPublicKey)
                
                var data = Array("Message to sign and encrypt".utf8)
                var output = [CK_BYTE](repeating: 0, count: 512)
                var outputLen = CK_ULONG(output.count)
                
                let rv = C_SignEncryptUpdate(hSession, &data, CK_ULONG(data.count), &output, &outputLen)
                appendLog("Test 1: Sign and Encrypt update → \(rv)")
            } else {
                appendLog("Test 1: Key pair generation failed")
            }
        }
    }

    func testDecryptVerifyUpdate() {
        appendLog("\n=== Testing C_DecryptVerifyUpdate ===")
        
        var hSession: CK_SESSION_HANDLE = 0
        let pin = "123456"
        
        func genericSetupWithLogin() -> Bool {
            resetTestState()
            _ = C_Initialize(nil)
            guard let slots = getSlotList(), !slots.isEmpty else { return false }
            _ = C_OpenSession(slots[0], CK_FLAGS(CKF_SERIAL_SESSION | CKF_RW_SESSION), nil, nil, &hSession)
            var pinStr = Array(pin.utf8)
            _ = C_Login(hSession, CK_USER_TYPE(CKU_USER), &pinStr, CK_ULONG(pinStr.count))
            return true
        }
        
        // Test Case 1: Decrypt and Verify update
        if genericSetupWithLogin() {
            var mech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS), pParameter: nil, ulParameterLen: 0)
            
            // Generate RSA key pair
            var keyGenMech = CK_MECHANISM(mechanism: CK_MECHANISM_TYPE(CKM_RSA_PKCS_KEY_PAIR_GEN), pParameter: nil, ulParameterLen: 0)
            var modulusBits = CK_ULONG(2048)
            var publicExponent: [CK_BYTE] = [0x01, 0x00, 0x01]
            var ckTrue = CK_BBOOL(CK_TRUE)
            
            var pubTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_VERIFY), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_MODULUS_BITS), pValue: &modulusBits, ulValueLen: CK_ULONG(MemoryLayout<CK_ULONG>.size)),
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_PUBLIC_EXPONENT), pValue: &publicExponent, ulValueLen: CK_ULONG(publicExponent.count))
            ]
            
            var privTemplate: [CK_ATTRIBUTE] = [
                CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_DECRYPT), pValue: &ckTrue, ulValueLen: CK_ULONG(MemoryLayout<CK_BBOOL>.size))
            ]
            
            var hPublicKey: CK_OBJECT_HANDLE = 0
            var hPrivateKey: CK_OBJECT_HANDLE = 0
            
            if C_GenerateKeyPair(hSession, &keyGenMech, &pubTemplate, CK_ULONG(pubTemplate.count), &privTemplate, CK_ULONG(privTemplate.count), &hPublicKey, &hPrivateKey) == CKR_OK {
                _ = C_DecryptInit(hSession, &mech, hPrivateKey)
                _ = C_VerifyInit(hSession, &mech, hPublicKey)
                
                var encryptedInput = Array("Encrypted and signed data".utf8)
                var output = [CK_BYTE](repeating: 0, count: 512)
                var outputLen = CK_ULONG(output.count)
                
                let rv = C_DecryptVerifyUpdate(hSession, &encryptedInput, CK_ULONG(encryptedInput.count), &output, &outputLen)
                appendLog("Test 1: Decrypt and Verify update → \(rv)")
            } else {
                appendLog("Test 1: Key pair generation failed")
            }
        }
    }

    func testGetFunctionList() {
        appendLog("\n=== Testing C_GetFunctionList ===")
        
        var rv: CK_RV = 0
        var funcListPtr: UnsafeMutablePointer<UnsafeMutablePointer<CK_FUNCTION_LIST>?>?
        
        // MARK: Test Case 1 - Get function list after finalize
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        
        rv = C_Finalize(nil)
        appendLog("C_Finalize → \(rv)")
        
        var funcList1: UnsafeMutablePointer<CK_FUNCTION_LIST>? = nil
        rv = C_GetFunctionList(&funcList1)
        appendLog("Test 1: Get function list after finalize → \(rv)")
        
        // MARK: Test Case 2 - Passing NULL as argument
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        
        rv = C_GetFunctionList(nil)
        appendLog("Test 2: Get function list with NULL pointer → \(rv)")
        
        // MARK: Test Case 3 - Passing correct argument for GetFunctionList
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        
        var funcList3: UnsafeMutablePointer<CK_FUNCTION_LIST>? = nil
        rv = C_GetFunctionList(&funcList3)
        appendLog("Test 3: Get function list with valid pointer → \(rv)")
    }

    
    func testGetInfo() {
        appendLog("\n=== Testing C_GetInfo ===")

        // MARK: Test Case 1 - Passing NULL as C_GetInfo argument
        resetTestState()
        var rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")

        rv = C_GetInfo(nil)
        appendLog("Test 1: Passing NULL as C_GetInfo argument → \(rv)")

        // MARK: Test Case 2 - Calling C_GetInfo after calling C_Finalize
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")
        rv = C_Finalize(nil)
        appendLog("C_Finalize → \(rv)")

        var info1 = CK_INFO()
        rv = C_GetInfo(&info1)
        appendLog("Test 2: Calling C_GetInfo after calling C_Finalize → \(rv)")

        // MARK: Test Case 3 - Passing correct argument and checking properties
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")

        var info2 = CK_INFO()
        rv = C_GetInfo(&info2)
        appendLog("Test 3: Passing correct argument and checking properties → \(rv)")

        if rv == CKR_OK {
            // Convert fixed-size C arrays (tuples) to Swift strings safely
            let manufacturerID = withUnsafeBytes(of: info2.manufacturerID) { rawPtr -> String in
                let bytes = Array(rawPtr)
                return String(bytes: bytes, encoding: .ascii)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            }

            let libraryDescription = withUnsafeBytes(of: info2.libraryDescription) { rawPtr -> String in
                let bytes = Array(rawPtr)
                return String(bytes: bytes, encoding: .ascii)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            }

            appendLog("Cryptoki Version: \(info2.cryptokiVersion.major).\(info2.cryptokiVersion.minor)")
            appendLog("Manufacturer ID: \(manufacturerID)")
            appendLog("Library Description: \(libraryDescription)")
            appendLog("Library Version: \(info2.libraryVersion.major).\(info2.libraryVersion.minor)")
        }

        // MARK: Test Case 4 - Calling C_GetInfo again
        resetTestState()
        rv = C_Initialize(nil)
        appendLog("C_Initialize → \(rv)")

        var info3 = CK_INFO()
        rv = C_GetInfo(&info3)
        appendLog("First call to C_GetInfo → \(rv)")

        let rv2 = C_GetInfo(&info3)
        appendLog("Test 4: Calling C_GetInfo again → \(rv2)")
    }


    
}


        
