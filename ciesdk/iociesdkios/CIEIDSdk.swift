//
//  CIEIDSdk.swift
//  NFCTest
//

import UIKit
import CoreNFC
import Security

extension URL {
    var queryParameters: QueryParameters { return QueryParameters(url: self) }
}

class QueryParameters {
    let queryItems: [URLQueryItem]
    init(url: URL?) {
        queryItems = URLComponents(string: url?.absoluteString ?? "")?.queryItems ?? []
        print(queryItems)
    }
    subscript(name: String) -> String? {
        return queryItems.first(where: { $0.name == name })?.value
    }
}

struct Constants {
    static let KEY_VALUE = "value"
    static let KEY_AUTHN_REQUEST_STRING = "authnRequestString"
    static let KEY_NAME = "name"
    static let KEY_NEXT_UTL = "nextUrl"
    static let KEY_OP_TEXT = "OpText"
    static let KEY_LOGO = "imgUrl"
    static let generaCodice = "generaCodice"
    static let authnRequest = "authnRequest"
    static let BASE_URL_IDP = "https://collaudo.idserver.servizicie.interno.gov.it/idp/"
    //PRODUZIONE
    //"https://idserver.servizicie.interno.gov.it/idp/"
    //COLLAUDO
    //"https://idserver.servizicie.interno.gov.it:8443/idp/"
}

struct CieData: Codable {
    var url = ""
    var pidData = PidData()
}

struct PidData: Codable {
    var name = ""
    var surname = ""
    var fiscalCode = ""
    var birthDate = ""
}

enum AlertMessageKey : String {
    case readingInstructions
    case moreTags
    case readingInProgress
    case readingSuccess
    case invalidCard
    case tagLost
    case cardLocked
    case wrongPin1AttemptLeft
    case wrongPin2AttemptLeft
}


@available(iOS 13.0, *)
@objc(CIEIDSdk)
public class CIEIDSdk : NSObject, NFCTagReaderSessionDelegate {
    
    private var readerSession: NFCTagReaderSession?
    private var cieTag: NFCISO7816Tag?
    private var cieTagReader : CIETagReader?
    private var completedHandler: ((String?, String?)->())!
    
    private var url : String?
    private var pin : String?
    private var alertMessages : [AlertMessageKey : String]
    
    @objc public var attemptsLeft : Int;
    
    override public init( ) {
        
        
        attemptsLeft = 3
        cieTag = nil
        cieTagReader = nil
        url = nil
        alertMessages = [AlertMessageKey : String]()
        super.init()
        self.initMessages()
    }
    
    private func initMessages(){
        /* alert default values */
        alertMessages[AlertMessageKey.readingInstructions] = "Tieni la tua carta d’identità elettronica sul retro dell’iPhone, nella parte in alto."
        alertMessages[AlertMessageKey.moreTags] = "Sono stati individuate più carte NFC. Per favore avvicina una carta alla volta."
        alertMessages[AlertMessageKey.readingInProgress] = "Lettura in corso, tieni ferma la carta ancora per qualche secondo..."
        alertMessages[AlertMessageKey.readingSuccess] = "Lettura avvenuta con successo.\nPuoi rimuovere la carta mentre completiamo la verifica dei dati."
        /* errors */
        alertMessages[AlertMessageKey.invalidCard] = "La carta utilizzata non sembra essere una Carta di Identità Elettronica (CIE)."
        alertMessages[AlertMessageKey.tagLost] = "Hai rimosso la carta troppo presto."
        alertMessages[AlertMessageKey.cardLocked] = "Carta CIE bloccata"
        alertMessages[AlertMessageKey.wrongPin1AttemptLeft] = "PIN errato, hai ancora 1 tentativo"
        alertMessages[AlertMessageKey.wrongPin2AttemptLeft] = "PIN errato, hai ancora 2 tentativi"
    }
    
    @objc
    public func setAlertMessage(key: String, value: String){
        let maybeKey = AlertMessageKey(rawValue: key)
        if(maybeKey != nil){
            alertMessages[maybeKey!] = value
        }
    }
    
    public func start(completed: @escaping (String?, String?)->() ) {
        self.completedHandler = completed
        
        guard NFCTagReaderSession.readingAvailable else {
            completedHandler( ErrorHelper.TAG_ERROR_NFC_NOT_SUPPORTED, nil)//TagError(errorDescription: "NFCNotSupported"))
            return
        }
        
        Log.debug( "authenticate" )
        
        if NFCTagReaderSession.readingAvailable {
            Log.debug( "readingAvailable" )
            readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            readerSession?.alertMessage = alertMessages[AlertMessageKey.readingInstructions]!
            readerSession?.begin()
        }
    }
    
    @objc
    public func post(url: String, pin: String, completed: @escaping (String?, String?)->() ) {
        self.pin = pin
        self.url = url
        
        self.start(completed: completed)
    }
    
    @objc
    public func hasNFCFeature() -> Bool {
        return NFCTagReaderSession.readingAvailable
    }
    
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        Log.debug( "tagReaderSessionDidBecomeActive" )
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        Log.debug( "tagReaderSession:didInvalidateWithError - \(error)" )
        if(self.readerSession != nil)
        {
            let nfcError = error as! NFCReaderError
            let errorMessage = ErrorHelper.nativeError(errorMessage: ErrorHelper.decodeError(error:UInt16(nfcError.errorCode)))
            self.readerSession?.invalidate(errorMessage:errorMessage)
            self.completedHandler(ErrorHelper.TAG_ERROR_SESSION_INVALIDATED, nil)
        }
        
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Log.debug( "tagReaderSession:didDetect - \(tags[0])" )
        if tags.count > 1 {
            session.alertMessage = alertMessages[AlertMessageKey.moreTags]!
            return
        }
        
        let tag = tags.first!
        
        switch tags.first! {
        case let .iso7816(tag):
            cieTag = tag
        default:
            //self.readerSession = nil
            self.readerSession?.invalidate(errorMessage: alertMessages[AlertMessageKey.invalidCard]!)
            self.completedHandler("ON_TAG_DISCOVERED_NOT_CIE", nil)
            return
        }
        
        // Connect to tag
        session.connect(to: tag) { [unowned self] (error: Error?) in
            if error != nil {
                let  session = self.readerSession
                session?.invalidate(errorMessage: alertMessages[AlertMessageKey.tagLost]!)
                // self.readerSession = nil
                self.completedHandler("ON_TAG_LOST", nil)
                return
            }
            
            self.readerSession?.alertMessage = alertMessages[AlertMessageKey.readingInProgress]!
            self.cieTagReader = CIETagReader(tag:self.cieTag!)
            self.startReading( )
        }
    }
    
    
    func cfDataToBase64(cfData: CFData) -> String? {
        let length = CFDataGetLength(cfData)
        var bytes = [UInt8](repeating: 0, count: length)
        CFDataGetBytes(cfData, CFRangeMake(0, length), &bytes)
        
        let data = Data(bytes: bytes, count: length)
        return data.base64EncodedString()
    }
    
    func extractDateOfBirth(from fiscalCode: String) -> String? {
        // Ensure that the input Fiscal Code is at least 5 characters long
        guard fiscalCode.count >= 5 else {
            return nil
        }
        
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd"
        
        // Extract the birth year (first two characters)
        let birthYearSubstring = fiscalCode[fiscalCode.index(fiscalCode.startIndex, offsetBy: 6)..<fiscalCode.index(fiscalCode.startIndex, offsetBy: 8)]
        let birthYear = getFullYear(year: Int(birthYearSubstring)!)
        
        // Extract the month of birth (third character)
        let monthCode = fiscalCode[fiscalCode.index(fiscalCode.startIndex, offsetBy: 8)]
        let month = monthCodeToNumber(String(monthCode))
        
        // Extract the day of birth (fourth and fifth characters)
        let daySubstring = fiscalCode[fiscalCode.index(fiscalCode.startIndex, offsetBy: 9)..<fiscalCode.index(fiscalCode.startIndex, offsetBy: 11)]
        
        var day = Int(daySubstring)
        if (day! > 31) {
            day! -= 40
        }
        
        // Create a Date object from the extracted components
        var dateComponents = DateComponents()
        dateComponents.year = birthYear
        dateComponents.month = month
        dateComponents.day = day
        
        // Convert Date to String
        if let date = Calendar.current.date(from: dateComponents) {
            let dateString = dateFormatter.string(from: date)
            return dateString
        } else {
            return nil
        }
    }
    
    func getFullYear(year: Int) -> Int {
        let currentYear = Calendar.current.component(.year, from: Date())
        let century = (currentYear / 100) * 100
        let lastTwoDigits = currentYear - century
        
        if year > lastTwoDigits {
            return (century - 100) + year
        } else {
            return century + year
        }
    }
    
    func monthCodeToNumber(_ code: String) -> Int {
        let monthCodes = "ABCDEFGHIJKLMNO"
        if let index = monthCodes.firstIndex(of: Character(code)) {
            return monthCodes.distance(from: monthCodes.startIndex, to: index) + 1 // Add 1 to convert from 0-based index to month number (1-based).
        }
        return 1 // Default to January if the code is not recognized.
    }
    
    
    
    func x509CertificateToJSON(certificateData: Data) -> String? {
        
        do {
            let x509 = try X509Certificate(data: certificateData)
            
            var pidCieData = PidData()
            pidCieData.name = x509.subject(oid: OID.givenName)?.first ?? ""
            pidCieData.surname = x509.subject(oid: OID.surname)?.first ?? ""
            let commonName = x509.subject(oid: OID.commonName)?.first
            
            if let taxId = commonName?.split(separator: "/").first {
                pidCieData.fiscalCode = String(taxId)
                pidCieData.birthDate = extractDateOfBirth(from: pidCieData.fiscalCode) ?? ""
            }
            
            var certificateInfo = CieData()
            certificateInfo.url = "https://collaudo.idserver.servizicie.interno.gov.it/idp/Authn/X509MobileTLS13Second?"
            certificateInfo.pidData = pidCieData
            
            let encodedData = try JSONEncoder().encode(certificateInfo)
            let jsonString = String(data: encodedData,
                                    encoding: .utf8)
            return jsonString
            
        } catch {
            print(error)
        }
        
        return nil
        
    }
    
    
    func startReading()
    {
        // let url1 = URL(string: self.url!.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
        // let value = url1!.queryParameters[Constants.KEY_VALUE]!
        // let name = url1!.queryParameters[Constants.KEY_NAME]!
        // let authnRequest = url1!.queryParameters[Constants.KEY_AUTHN_REQUEST_STRING]!
        // let nextUrl = url1!.queryParameters[Constants.KEY_NEXT_UTL]!
        // let opText = url1!.queryParameters[Constants.KEY_OP_TEXT]!
        // let logo = url1?.queryParameters[Constants.KEY_LOGO]!
        
        // let params = "\(value)=\(name)&\(Constants.authnRequest)=\(authnRequest)&\(Constants.generaCodice)=1"
        let params = ""
        self.cieTagReader?.post(url: Constants.BASE_URL_IDP, pin: self.pin!, data: params, completed: { [self] (data, error) in
            
            let  session = self.readerSession
            //self.readerSession = nil
            // session?.invalidate()
            Log.debug( "error- \(error)" )
            switch(error)
            {
            case 0:  // OK
                session?.alertMessage = self.alertMessages[AlertMessageKey.readingSuccess]!
                // let response = String(data: data!, encoding: .utf8)
                // let codiceServer = String((response?.split(separator: ":")[1])!)
                // let newurl = nextUrl + "?" + name + "=" + value + "&login=1&codice=" + codiceServer
                self.completedHandler(nil, x509CertificateToJSON(certificateData: data!))
                session?.invalidate()
                break;
            case 0x63C0,0x6983: // PIN LOCKED
                self.attemptsLeft = 0
                session?.invalidate(errorMessage: self.alertMessages[AlertMessageKey.cardLocked]!)
                self.completedHandler("ON_CARD_PIN_LOCKED", nil)
                break;
                
            case 0x63C1: // WRONG PIN 1 ATTEMPT LEFT
                self.attemptsLeft = 1
                self.completedHandler("ON_PIN_ERROR", nil)
                session?.invalidate(errorMessage: self.alertMessages[AlertMessageKey.wrongPin1AttemptLeft]!)
                break;
                
            case 0x63C2: // WRONG PIN 2 ATTEMPTS LEFT
                self.attemptsLeft = 2
                self.completedHandler("ON_PIN_ERROR", nil)
                session?.invalidate(errorMessage: self.alertMessages[AlertMessageKey.wrongPin2AttemptLeft]!)
                break;
                
            default: // OTHER ERROR
                self.completedHandler(ErrorHelper.decodeError(error: error), nil)
                session?.invalidate(errorMessage:ErrorHelper.nativeError(errorMessage:ErrorHelper.decodeError(error: error)))
                break;
                
            }
        })
    }
}
