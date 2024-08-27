import System;
import Fiddler;
import Fiddler.WebFormats;
import System.Security.Cryptography;

class Handlers {
        
    static function CreateHMACSHA256(message: String, secret: String) {
        var encoding = new System.Text.ASCIIEncoding();
        var keyByte = encoding.GetBytes(secret);
        var messageBytes = encoding.GetBytes(message);
        var hmacsha256 = new HMACSHA256(keyByte);
        var hashmessage = hmacsha256.ComputeHash(messageBytes);
        return Convert.ToBase64String(hashmessage);
    }

    static function OnBeforeResponse(session: Session) {
        if (session.oResponse.headers.Exists("PsySig")) {
            if (session.GetRequestBodyAsString().Contains("Auth/AuthPlayer")) {
                session.utilReplaceInResponse('"UseWebSocket":true', '"UseWebSocket":false');
            }
            session.oResponse["PsySig"] = CreateHMACSHA256(session.oResponse["PsyTime"] + "-" + session.GetResponseBodyAsString(), "3b932153785842ac927744b292e40e52");
        }
    }
        
}