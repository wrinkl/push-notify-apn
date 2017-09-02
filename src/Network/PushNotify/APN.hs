-- |
-- Module: APN
-- Copyright: (C) 2017, memrange UG
-- License: BSD3
-- Maintainer: Hans-Christian Esperer <hc@memrange.io>
-- Stability: experimental
-- Portability: portable
--
-- Send push notifications using Apple's HTTP2 APN API
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}

module Network.PushNotify.APN
    ( ApnSession
    , JsonAps
    , JsonApsAlert
    , JsonApsMessage
    , ApnMessageResult(..)
    , ApnToken
    , sendMessage
    , sendSilentMessage
    , newSession
    , sendRawMessage
    , emptyMessage
    , setSound
    , clearSound
    , setCategory
    , clearCategory
    , setBadge
    , clearBadge
    , alertMessage
    , setAlertMessage
    , clearAlertMessage
    , newMessage
    , newMessageWithCustomPayload
    , hexEncodedToken
    , rawToken
    ) where

import Control.Concurrent
import Control.Concurrent.QSem
import Control.Exception
import Control.Monad
import Data.Aeson
import Data.Aeson.Types
import Data.ByteString (ByteString)
import Data.Char (toLower)
import Data.Default (def)
import Data.Int
import Data.IORef
import Data.Map.Strict (Map)
import Data.Text (Text)
import Data.Time.Clock.POSIX
import Data.X509
import Data.X509.CertificateStore
import GHC.Generics
import Network.HTTP2.Client
import Network.HTTP2.Client.Helpers
import Network.TLS hiding (sendData)
import Network.TLS.Extra.Cipher
import System.Random

import qualified Data.ByteString as S
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as L
import qualified Data.List as DL
import qualified Data.Map.Strict as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import qualified Network.HTTP2 as HTTP2
import qualified Network.HPACK as HTTP2

-- | A session that manages connections to Apple's push notification service
data ApnSession = ApnSession
    { apnSessionPool                 :: !(IORef [ApnConnection])
    , apnSessionConnectionInfo       :: !ApnConnectionInfo
    , apnSessionConnectionManager    :: !ThreadId }

-- | Information about an APN connection
data ApnConnectionInfo = ApnConnectionInfo
    { aciCertPath                    :: !FilePath
    , aciCertKey                     :: !FilePath
    , aciCaPath                      :: !FilePath
    , aciHostname                    :: !Text
    , aciMaxConcurrentStreams        :: !Int
    , aciTopic                       :: !ByteString }

-- | A connection to an APN API server
data ApnConnection = ApnConnection
    { apnConnectionConnection        :: !Http2Client
    , apnConnectionInfo              :: !ApnConnectionInfo
    , apnConnectionWorkerPool        :: !QSem
    , apnConnectionLastUsed          :: !Int64
    , apnConnectionFlowControlWorker :: !ThreadId }

-- | An APN token used to uniquely identify a device
newtype ApnToken = ApnToken { unApnToken :: ByteString }

-- | Create a token from a raw bytestring
rawToken
    :: ByteString
    -- ^ The bytestring that uniquely identifies a device (APN token)
    -> ApnToken
rawToken = ApnToken . B16.encode

-- | Create a token from a hex encoded text
hexEncodedToken
    :: Text
    -- ^ The base16 (hex) encoded unique identifier for a device (APN token)
    -> ApnToken
hexEncodedToken = ApnToken . B16.encode . fst . B16.decode . TE.encodeUtf8

-- | The result of a send request
data ApnMessageResult = ApnMessageResultOk
                      | ApnMessageResultFatalError
                      | ApnMessageResultTemporaryError
                      | ApnMessageResultTokenNoLongerValid
    deriving (Enum, Eq, Show)

-- | The specification of a push notification's message body
data JsonApsAlert = JsonApsAlert
    { jaaTitle                       :: !Text
    -- ^ A short string describing the purpose of the notification.
    , jaaBody                        :: !Text
    -- ^ The text of the alert message.
    } deriving (Generic, Show)

instance ToJSON JsonApsAlert where
    toJSON     = genericToJSON     defaultOptions
        { fieldLabelModifier = drop 3 . map toLower }

-- | Push notification message's content
data JsonApsMessage
    -- | Push notification message's content
    = JsonApsMessage
    { jamAlert                       :: !(Maybe JsonApsAlert)
    -- ^ A text to display in the notification
    , jamBadge                       :: !(Maybe Int)
    -- ^ A number to display next to the app's icon. If set to (Just 0), the number is removed.
    , jamSound                       :: !(Maybe Text)
    -- ^ A sound to play, that's located in the Library/Sounds directory of the app
    -- This should be the name of a sound file in the application's main bundle, or
    -- in the Library/Sounds directory of the app.
    , jamCategory                    :: !(Maybe Text)
    -- ^ The category of the notification. Must be registered by the app beforehand.
    } deriving (Generic, Show)

-- | Create an empty apn message
emptyMessage :: JsonApsMessage
emptyMessage = JsonApsMessage Nothing Nothing Nothing Nothing

-- | Set a sound for an APN message
setSound
    :: Text
    -- ^ The sound to use (either "default" or something in the application's bundle)
    -> JsonApsMessage
    -- ^ The message to modify
    -> JsonApsMessage
setSound s a = a { jamSound = Just s }

-- | Clear the sound for an APN message
clearSound
    :: JsonApsMessage
    -- ^ The message to modify
    -> JsonApsMessage
clearSound a = a { jamSound = Nothing }

-- | Set the category part of an APN message
setCategory
    :: Text
    -> JsonApsMessage
    -- ^ The message to modify
    -> JsonApsMessage
setCategory c a = a { jamCategory = Just c }

-- | Clear the category part of an APN message
clearCategory
    :: JsonApsMessage
    -- ^ The message to modify
    -> JsonApsMessage
clearCategory a = a { jamCategory = Nothing }

-- | Set the badge part of an APN message
setBadge
    :: Int
    -> JsonApsMessage
    -- ^ The message to modify
    -> JsonApsMessage
setBadge i a = a { jamBadge = Just i }

-- | Clear the badge part of an APN message
clearBadge
    :: JsonApsMessage
    -- ^ The message to modify
    -> JsonApsMessage
clearBadge a = a { jamBadge = Nothing }

-- | Create a new APN message with an alert part
alertMessage
    :: Text
    -- ^ The title of the message
    -> Text
    -- ^ The body of the message
    -> JsonApsMessage
alertMessage title text = setAlertMessage title text emptyMessage

-- | Set the alert part of an APN message
setAlertMessage
    :: Text
    -- ^ The title of the message
    -> Text
    -- ^ The body of the message
    -> JsonApsMessage
    -- ^ The message to alter
    -> JsonApsMessage
setAlertMessage title text a = a { jamAlert = Just jam }
  where
    jam = JsonApsAlert title text

-- | Remove the alert part of an APN message
clearAlertMessage
    :: JsonApsMessage
    -- ^ The message to modify
    -> JsonApsMessage
clearAlertMessage a = a { jamAlert = Nothing }

instance ToJSON JsonApsMessage where
    toJSON     = genericToJSON     defaultOptions
        { fieldLabelModifier = drop 3 . map toLower }

-- | A push notification message
data JsonAps
    -- | A push notification message
    = JsonAps
    { jaAps                          :: !JsonApsMessage
    -- ^ The main content of the message
    , jaAppSpecificContent           :: !(Maybe Text)
    -- ^ Extra information to be used by the receiving app
    } deriving (Generic, Show)

instance ToJSON JsonAps where
    toJSON     = genericToJSON     defaultOptions
        { fieldLabelModifier = drop 2 . map toLower }

-- | Prepare a new apn message consisting of a
-- standard message without a custom payload
newMessage
    :: JsonApsMessage
    -- ^ The standard message to include
    -> JsonAps
newMessage = flip JsonAps Nothing

-- | Prepare a new apn message consisting of a
-- standard message and a custom payload
newMessageWithCustomPayload
    :: JsonApsMessage
    -- ^ The message
    -> Text
    -- ^ The custom payload
    -> JsonAps
newMessageWithCustomPayload message payload =
    JsonAps message (Just payload)

-- | Start a new session for sending APN messages. A session consists of a
-- connection pool of connections to the APN servers, while each connection has a
-- pool of workers that create HTTP2 streams to send individual push
-- notifications.
newSession
    :: FilePath
    -- ^ Path to the client certificate key
    -> FilePath
    -- ^ Path to the client certificate
    -> FilePath
    -- ^ Path to the CA
    -> Bool
    -- ^ Sandbox?
    -> Int
    -- ^ How many messages will be sent in parallel? This corresponds to the number of http2 streams open in parallel; 100 seems to be a default value.
    -> ByteString
    -- ^ Topic (bundle name of the app)
    -> IO ApnSession
newSession certKey certPath caPath dev maxparallel topic = do
    let hostname = if dev
            then "api.development.push.apple.com"
            else "api.push.apple.com"
        connInfo = ApnConnectionInfo certPath certKey caPath hostname maxparallel topic
    connections <- newIORef []
    connectionManager <- forkIO $ manage 1800 connections
    return $ ApnSession connections connInfo connectionManager

getConnection :: ApnSession -> IO ApnConnection
getConnection s = do
    let pool = apnSessionPool s
        ci = apnSessionConnectionInfo s
    connections <- readIORef pool
    let len = length connections
    if len == 0
    then do
        conn <- newConnection ci
        atomicModifyIORef' pool (\a -> (conn:a, ()))
        return conn
    else do
        num <- randomRIO (0, len - 1)
        currtime <- round <$> getPOSIXTime :: IO Int64
        let conn = connections !! num
            conn1 = conn { apnConnectionLastUsed=currtime }
        atomicModifyIORef' pool (\a -> (replaceNth num conn1 a, ()))
        return conn1

replaceNth n newVal (x:xs)
    | n == 0 = newVal:xs
    | otherwise = x:replaceNth (n-1) newVal xs

manage :: Int64 -> IORef [ApnConnection] -> IO ()
manage timeout ioref = forever $ do
    currtime <- round <$> getPOSIXTime :: IO Int64
    let minTime = currtime - timeout
    expiredOnes <- atomicModifyIORef' ioref
        (foldl ( \(a,b) i -> if apnConnectionLastUsed i < minTime then (a, (i:b) ) else ( (i:a) ,b)) ([],[]))
    mapM_ closeApnConnection expiredOnes
    threadDelay 60000000


closeApnConnection :: ApnConnection -> IO ()
closeApnConnection apnConnection = do
    putStrLn "Closing connection, sending goaway"
    _gtfo (apnConnectionConnection apnConnection) HTTP2.NoError ""

newConnection :: ApnConnectionInfo -> IO ApnConnection
newConnection aci = do
    putStrLn "Starting new connection..."
    Just castore <- readCertificateStore $ aciCaPath aci
    Right credential <- credentialLoadX509 (aciCertPath aci) (aciCertKey aci)
    let credentials = Credentials [credential]
        shared      = def { sharedCredentials = credentials
                          , sharedCAStore=castore }
        maxConcurrentStreams = aciMaxConcurrentStreams aci
        clip = ClientParams
            { clientUseMaxFragmentLength=Nothing
            , clientServerIdentification=(T.unpack hostname, undefined)
            , clientUseServerNameIndication=True
            , clientWantSessionResume=Nothing
            , clientShared=shared
            , clientHooks=def
                { onCertificateRequest=const . return . Just $ credential }
            , clientDebug=DebugParams { debugSeed=Nothing, debugPrintSeed=const $ return () }
            , clientSupported=def
                { supportedVersions=[ TLS12 ]
                , supportedCiphers=ciphersuite_strong }
            }

        conf = [ (HTTP2.SettingsMaxFrameSize, 16384)
               , (HTTP2.SettingsMaxConcurrentStreams, maxConcurrentStreams)
               , (HTTP2.SettingsMaxHeaderBlockSize, 4096)
               , (HTTP2.SettingsInitialWindowSize, 65536)
               , (HTTP2.SettingsEnablePush, 1)
               ]

        hostname = aciHostname aci
    client <- newHttp2Client (T.unpack hostname) 443 4096 4096 clip conf
    flowWorker <- forkIO $ forever $ do
        updated <- _updateWindow $ _incomingFlowControl client
        when updated $ putStrLn "sending flow-control update"
        threadDelay 1000000


--    let largestWindowSize = HTTP2.maxWindowSize - HTTP2.defaultInitialWindowSize
--    _addCredit (_incomingFlowControl client) largestWindowSize
--    putStrLn "addCredit called."
--    _ <- forkIO $ forever $ do
--        threadDelay 1000000
--        _updateWindow $ _incomingFlowControl client
--        putStrLn "updateWindow callde."


    -- workerpool <- createPool (return ()) (const $ return ()) 1 600 maxConcurrentStreams
    workersem <- newQSem maxConcurrentStreams
    currtime <- round <$> getPOSIXTime :: IO Int64
    return $ ApnConnection client aci workersem currtime flowWorker

-- | Send a raw payload as a push notification message (advanced)
sendRawMessage
    :: ApnSession
    -- ^ Session to use
    -> ApnToken
    -- ^ Device to send the message to
    -> ByteString
    -- ^ The message to send
    -> IO ApnMessageResult
sendRawMessage s token payload = do
    c <- getConnection s
    res <- sendApnRaw c token payload
    case res of
        Left tmc   -> return ApnMessageResultTemporaryError -- TODO: Spawn new connection depending on poolsize
        Right res1 -> return res1

-- | Send a push notification message.
sendMessage
    :: ApnSession
    -- ^ Session to use
    -> ApnToken
    -- ^ Device to send the message to
    -> JsonAps
    -- ^ The message to send
    -> IO ApnMessageResult
sendMessage s token payload = do
    c <- getConnection s
    let message = L.toStrict $ encode payload
    res <- sendApnRaw c token message
    case res of
        Left tmc   -> return ApnMessageResultTemporaryError -- TODO: Spawn new connection depending on poolsize
        Right res1 -> return res1

-- | Send a silent push notification
sendSilentMessage
    :: ApnSession
    -- ^ Session to use
    -> ApnToken
    -- ^ Device to send the message to
    -> IO ApnMessageResult
sendSilentMessage s token = do
    c <- getConnection s
    let message = "{\"aps\":{\"content-available\":1}}"
    res <- sendApnRaw c token message
    case res of
        Left tmc   -> return ApnMessageResultTemporaryError -- TODO: Spawn new connection depending on poolsize
        Right res1 -> return res1

-- | Send a push notification message.
sendApnRaw
    :: ApnConnection
    -- ^ Connection to use
    -> ApnToken
    -- ^ Device to send the message to
    -> ByteString
    -- ^ The message to send
    -> IO (Either TooMuchConcurrency ApnMessageResult)
sendApnRaw connection token message = bracket_
  (waitQSem (apnConnectionWorkerPool connection))
  (signalQSem (apnConnectionWorkerPool connection)) $ do
    let headers = [ ( ":method", "POST" )
                  , ( ":scheme", "https" )
                  , ( ":authority", TE.encodeUtf8 hostname )
                  , ( ":path", "/3/device/" `S.append` token1 )
                  , ( "apns-topic", topic ) ]
        aci = apnConnectionInfo connection
        hostname = aciHostname aci
        topic = aciTopic aci
        client = apnConnectionConnection connection
        token1 = unApnToken token

    _startStream client $ \stream ->
        let init = _headers stream headers id
            handler isfc osfc = do
                -- sendData client stream (HTTP2.setEndStream) message
                upload message client (_outgoingFlowControl client) stream osfc
                hdrs <- _waitHeaders stream
                let (frameHeader, streamId, errOrHeaders) = hdrs
                case errOrHeaders of
                    Left err -> return ApnMessageResultTemporaryError
                    Right hdrs1 -> do
                        let Just status = DL.lookup ":status" hdrs1
                        return $ case status of
                            "200" -> ApnMessageResultOk
                            "400" -> ApnMessageResultFatalError
                            "403" -> ApnMessageResultFatalError
                            "405" -> ApnMessageResultFatalError
                            "410" -> ApnMessageResultTokenNoLongerValid
                            "413" -> ApnMessageResultFatalError
                            "429" -> ApnMessageResultTemporaryError
                            "500" -> ApnMessageResultTemporaryError
                            "503" -> ApnMessageResultTemporaryError           
--                let recv = do
--                        print "_waitData"
--                        (fh, x) <- _waitData stream
--                        print ("data", fmap (\bs -> (S.length bs, S.take 64 bs)) x)
--                        print fh
--                        when (not $ HTTP2.testEndStream (HTTP2.flags fh)) $ do
--                            print "testEndStream"
--                            _updateWindow isfc
--                            print "updateWindow"
--                            recv
                -- recv
        in StreamDefinition init handler
