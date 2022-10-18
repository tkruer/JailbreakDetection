import Foundation
import UIKit


public struct JailbreakDetection {

    public init() {
    }
    
    func isJailbroken() -> Bool {
            
            guard let cydiaUrlScheme = NSURL(string: "cydia://package/com.example.package") else { return false }
            if UIApplication.shared.canOpenURL(cydiaUrlScheme as URL) {
                print("[Jailbreak Detection]:\tCydia URL scheme.")
                return true
            }
            
            #if arch(i386) || arch(x86_64)
                // This is a Simulator feature - might honestly remove this
                print("[Jailbreak Detection]:\tSimulator detected.")
                return true
            #endif
             
            
            let fileManager = FileManager.default
            if fileManager.fileExists(atPath: "/Applications/Cydia.app") ||
                fileManager.fileExists(atPath: "/Library/MobileSubstrate/MobileSubstrate.dylib") ||
                fileManager.fileExists(atPath: "/bin/bash") ||
                fileManager.fileExists(atPath: "/usr/sbin/sshd") ||
                fileManager.fileExists(atPath: "/etc/apt") ||
                fileManager.fileExists(atPath: "/usr/bin/ssh") ||
                fileManager.fileExists(atPath: "/private/var/lib/apt") {
                print("[Jailbreak Detection]:\tUncommon file exists.")
                return true
            }
            
            if canOpen(path: "/Applications/Cydia.app") ||
                canOpen(path: "/Library/MobileSubstrate/MobileSubstrate.dylib") ||
                canOpen(path: "/bin/bash") ||
                canOpen(path: "/usr/sbin/sshd") ||
                canOpen(path: "/etc/apt") ||
                canOpen(path: "/usr/bin/ssh") {
                print("[Jailbreak Detection]:\tCan open uncommon path.")
                return true
            }
            
            let path = "/private/" + NSUUID().uuidString
            do {
                try "anyString".write(toFile: path, atomically: true, encoding: String.Encoding.utf8)
                try fileManager.removeItem(atPath: path)
                print("[Jailbreak Detection]:\tCreate file in /private/.")
                return true
            } catch {
                return false
            }
        }
        
    func canOpen(path: String) -> Bool {
            let file = fopen(path, "r")
            guard file != nil else { return false }
            fclose(file)
            return true
        }
}

