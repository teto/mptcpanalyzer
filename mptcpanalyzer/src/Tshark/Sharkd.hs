{-# LANGUAGE OverloadedStrings #-}
-- 
--
-- Format of request listed at <https://gitlab.com/wireshark/wireshark/-/wikis/sharkd-Request-Syntax#tap>
module Tshark.Sharkd (

    defaultSocketPath
  , launchSharkd
  , connectToSharkd
  , loadFile

  )
where

import Network.Socket
import Network.Socket.ByteString
import Data.Aeson
import Data.Aeson.Extra.Merge (lodashMerge)
import System.Process hiding (runCommand)
import qualified Control.Exception as E
import Data.ByteString.Lazy (toStrict)
import GHC.IO.Handle
import Control.Concurrent
import qualified Data.ByteString as S
import Foreign (Ptr)
import Foreign.C (CChar)


defaultSocketPath :: FilePath
defaultSocketPath = "/tmp/sharkd.sock"

basicPayload :: String -> Value
basicPayload method = object [
        "method" .= toJSON method
      , "jsonrpc" .= toJSON ("2.0" :: String)
      , "id" .= toJSON (1 ::Int)
      -- , "params" .= object [
      --     "file" .= pcapPath
      --   ]
      ]


basicPayloadStr :: String -> String
basicPayloadStr inside = "{'jsonrpc': '2.0', 'id': 1, 'method':'info'}"

launchSharkd :: FilePath -- ^ Unix socket path
      -> IO ()
launchSharkd socketPath = let
    createProc :: CreateProcess
    createProc = (proc "sharkd" [ socketPath ]) {
      delegate_ctlc = True
    }
  in do
    putStrLn $ "Launching " ++ show createProc
    (_, _, mbHerr, ph) <- createProcess createProc
    pure ()
    -- waitForProcess ph



connectToSharkd :: FilePath -> IO ()
connectToSharkd = undefined

-- TODO should return a Either String Value instead ?
sendRequestToSharkd :: FilePath -> Value -> IO (Either String Value)
sendRequestToSharkd sockPath payload = do
  -- withFdSocket sock (setCloseOnExecIfNeeded)
  -- socketPair
  -- addr
  -- {"jsonrpc":"2.0","id":1,"result":{"status":"OK"}},

  E.bracketOnError (socket AF_UNIX Stream defaultProtocol) close $ \sock -> do
      -- setSocketOption sock ReuseAddr 1
      -- withFdSocket sock setCloseOnExecIfNeeded
      -- withFdSocket sock setCloseOnExecIfNeeded
      -- bind sock $ addrAddress addr
      -- sock <- socket AF_UNIX Stream defaultProtocol
      putStrLn $ "connecting to socket " ++ show sockPath

      connect sock (SockAddrUnix sockPath)

      putStrLn "connected"
      -- m <- newEmptyMVar
      -- forkIO $ (listenForResponse h m)
      putStrLn $ "sending payload " ++ show payload
      let bsPayload = (toStrict $ encode payload ) <> "\n"
      putStrLn $ "sending payload " ++ show bsPayload
      sendAll sock bsPayload
      putStrLn "sent"
      -- threadDelay $ 1 * 10^6
      -- do msg <- recv conn 1024
      -- unless (C.null msg) $ do
      --   C.putStrLn msg 
      --   talk conn
      bs <- recv sock 1024
      putStrLn "recv"
      print bs
      return $ eitherDecodeStrict bs
      -- listen sock 1024
      -- return sock
  where
    -- socket AF_UNIX Stream defaultProtocol
    addr = defaultHints  { addrFamily = AF_UNIX, addrAddress = SockAddrUnix sockPath }
    -- sock = socket Stream 0

-- |
-- {"req":"load","file":"c:/traces/Contoso_01/web01/web01_00001_20161012151754.pcapng"}
loadFile :: FilePath -> FilePath -> IO ()
loadFile pcapPath sockPath =

  sendRequestToSharkd sockPath payload >> return ()
  where
    payload = lodashMerge (basicPayload "load") paramsPayload
    paramsPayload = (object [
        "params" .= object [
          "file" .= pcapPath
        ]
      ])

-- this works
getInfo :: FilePath -> IO ()
getInfo sockPath = sendRequestToSharkd sockPath payload >> return ()
  where
    payload = basicPayload "info"
    -- paramsPayload = (object [
    --     "params" .= object [
    --       "file" .= pcapPath
    --     ]
    --   ])

-- {"req":"status"}

getStatus :: Socket -> IO ()
getStatus sock = sendRequestToSharkd defaultSocketPath payload >> return ()
  where
    payload = object [
        "req" .= toJSON ("status" :: String)
      ]

-- {"req":"frames","filter":"frame.number<=20"}
-- getFrames
-- getFrames


-- listenForResponse ::  Handle -> MVar (Maybe S.ByteString) -> IO ()
-- listenForResponse h m = do  putStrLn "listening for response..."
--                             msg <- receiveResponse h
--                             putMVar m msg
--                             return ()
--   where

--     receiveResponse :: Handle -> IO (Maybe S.ByteString)
--     receiveResponse h = do
--         buf <- mallocBytes receiveBufSize
--         dataResp <- receiveMsg buf h
--         free buf
--         return dataResp

--     receiveMsg :: Ptr CChar -> Handle -> IO (Maybe S.ByteString)
--     receiveMsg buf h = do
--         putStrLn ("wait for data with timeout:" ++ show connectionTimeout ++ " ms\n")
--         dataAvailable <- waitForData h connectionTimeout
--         if not dataAvailable then (print "no message available...") >> return Nothing
--           else do
--             answereBytesRead <- hGetBufNonBlocking h buf receiveBufSize
--             Just `fmap` S.packCStringLen (buf,answereBytesRead)

--     waitForData ::  Handle -> Int -> IO (Bool)
--     waitForData h waitTime_ms = do
--       S.putStr "."
--       inputAvailable <- hWaitForInput h 10
--       if inputAvailable then return True 
--         else if waitTime_ms > 0
--               then waitForData h (waitTime_ms - 10)
--               else return False
