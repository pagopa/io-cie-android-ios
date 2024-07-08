//
//  CIEIDSdk.swift
//  NFCTest
//

import UIKit
import CoreNFC

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
    static let BASE_URL_IDP = "https://idserver.servizicie.interno.gov.it/idp/Authn/SSL/Login2"
    //PRODUZIONE
    //"https://idserver.servizicie.interno.gov.it/idp/"
    //COLLAUDO
    //"https://collaudo.idserver.servizicie.interno.gov.it/idp/"
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
    case genericError
}


@available(iOS 13.0, *)
@objc(CIEIDSdk)
public class CIEIDSdk : NSObject, NFCTagReaderSessionDelegate {
    
    private var readerSession: NFCTagReaderSession?
    private var cieTag: NFCISO7816Tag?
    private var cieTagReader : CIETagReader?
    private var completedHandler: ((String?, String?)->())!
    
    private var customIdpUrl: String?
    private var enableLog: Bool = false
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
    
    private func debugPrint(_ items: Any..., separator: String = " ", terminator: String = "\n") {
        if (self.enableLog) {
            print(items, separator, terminator)
        }
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
        alertMessages[AlertMessageKey.genericError] = "Qualcosa è andato storto"
    }
    
    @objc
    public func setAlertMessage(key: String, value: String){
        let maybeKey = AlertMessageKey(rawValue: key)
        if(maybeKey != nil){
            alertMessages[maybeKey!] = value
        }
    }
    
    @objc
    public func setCustomIdpUrl(url: String?) {
        self.customIdpUrl = url
        debugPrint("Custom idp url set: " + (url ?? "null"))
    }
    
    @objc
    public func enableLog(isEnabled: Bool) {
        self.enableLog = isEnabled
    }
    
    private func start(completed: @escaping (String?, String?)->() ) {
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
    
    func startReading()
    {
        
        guard let urlString = self.url?.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
              let parsedUrl = URL(string: urlString),
              let pin = self.pin
        else {
            return;
        }
        
        
        let value = parsedUrl.queryParameters[Constants.KEY_VALUE] ?? ""
        let name = parsedUrl.queryParameters[Constants.KEY_NAME] ?? ""
        let authnRequest = parsedUrl.queryParameters[Constants.KEY_AUTHN_REQUEST_STRING] ?? ""
        let nextUrl = parsedUrl.queryParameters[Constants.KEY_NEXT_UTL] ?? ""
        
        let params = "\(value)=\(name)&\(Constants.authnRequest)=\(authnRequest)&\(Constants.generaCodice)=1"
        
        let baseIdpUrl = self.customIdpUrl ?? Constants.BASE_URL_IDP
        debugPrint("baseIdpUrl " + baseIdpUrl)
        
        // It's safe to force unwrap when using UTF enconding, because swift string use Unicode internally
        let missingDataPlaceholder = "codice:XXX".data(using: .utf8)!
        
        self.cieTagReader?.post(
            url: baseIdpUrl,
            pin: pin,
            data: params,
            completed: { [weak self] (data, error) in
                guard let self = self else {
                    return
                }
                
                let  session = self.readerSession
                //self.readerSession = nil
                // session?.invalidate()
                Log.debug( "error- \(error)" )
                switch(error)
                {
                case 0:  // OK
                    session?.alertMessage = self.alertMessages[AlertMessageKey.readingSuccess]!
                    let response = String(data: data ?? missingDataPlaceholder, encoding: .utf8)
                    do {
                        guard let response = response else {
                            throw NSError(
                                domain: "ios-cie-sdk",
                                code: 100,
                                userInfo: [NSLocalizedDescriptionKey: "Response is nil."]
                            )
                        }
                        let components = response.split(separator: ":")
                        if components.count < 2 {
                            throw NSError(
                                domain: "ios-cie-sdk",
                                code: 101,
                                userInfo: [
                                    NSLocalizedDescriptionKey:
                                        "Expected component not found after splitting response."
                                ]
                            )
                        }
                        let serverCode = String(components[1])
                        let newurl = nextUrl + "?" + name + "=" + value + "&login=1&codice=" + serverCode
                        self.debugPrint("newurl \(newurl)")
                        self.completedHandler(nil, newurl)
                        session?.invalidate()
                    } catch {
                        self.debugPrint("An error occurred: \(error.localizedDescription)")
                        self.completedHandler("AUTHENTICATION_ERROR", nil)
                        session?.invalidate(errorMessage: self.alertMessages[AlertMessageKey.genericError]!)
                    }
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
