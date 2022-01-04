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
import Data.Aeson.Encode.Pretty
import Data.Aeson.Extra.Merge (lodashMerge)
import System.Process hiding (runCommand)
import qualified Control.Exception as E
import Data.ByteString.Lazy (toStrict)
import GHC.IO.Handle
import Control.Concurrent
import qualified Data.ByteString as S
import Foreign (Ptr)
import Foreign.C (CChar)
import Data.Aeson.Encoding (encodingToLazyByteString)


defaultSocketPath :: FilePath
defaultSocketPath = "/tmp/sharkd.sock"

basicPayload :: String -> Series
basicPayload method = 
        "method" .= toJSON method
        <> "jsonrpc" .= toJSON ("2.0" :: String)
        <> "id" .= toJSON (1 ::Int)
      -- , "params" .= object [
      --     "file" .= pcapPath
      --   ]



basicPayloadStr :: String -> String
basicPayloadStr inside = "{'jsonrpc': '2.0', 'id': 1, 'method':'info'}"


-- | Launches the wireshark daemon
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


-- | 
-- serializingConfig :: Config
-- serializingConfig = defConfig { confCompare = compare }

connectToSharkd :: FilePath -> IO ()
connectToSharkd = undefined

-- TODO should return a Either String Value instead ?
sendRequestToSharkd :: FilePath -> Encoding -> IO (Either String Value)
sendRequestToSharkd sockPath payload = do
  E.bracketOnError (socket AF_UNIX Stream defaultProtocol) close $ \sock -> do
      -- setSocketOption sock ReuseAddr 1
      -- withFdSocket sock setCloseOnExecIfNeeded
      -- sock <- socket AF_UNIX Stream defaultProtocol
      putStrLn $ "connecting to socket " ++ show sockPath

      connect sock (SockAddrUnix sockPath)

      putStrLn "connected"
      -- m <- newEmptyMVar
      -- forkIO $ (listenForResponse h m)
      putStrLn $ "sending payload " ++ show payload
      let bsPayload = (toStrict $ encodingToLazyByteString payload ) <> "\n"
      putStrLn $ "sending payload " ++ show bsPayload
      sendAll sock bsPayload
      putStrLn "sent"
      bs <- recv sock 1024
      putStrLn "recv"
      print bs
      return $ eitherDecodeStrict bs
  where
    -- socket AF_UNIX Stream defaultProtocol
    addr = defaultHints  { addrFamily = AF_UNIX, addrAddress = SockAddrUnix sockPath }

-- |
-- {"req":"load","file":"c:/traces/Contoso_01/web01/web01_00001_20161012151754.pcapng"}
loadFile :: FilePath -> FilePath -> IO ()
loadFile pcapPath sockPath =

  sendRequestToSharkd sockPath (pairs payload) >> return ()
  where
    payload = basicPayload "load" <> paramsPayload 
    paramsPayload = 
          "params" .= object [
            "file" .= pcapPath
          ]

-- this works
getInfo :: FilePath -> IO ()
getInfo sockPath = sendRequestToSharkd sockPath (pairs payload) >> return ()
  where
    payload = basicPayload "info"

-- {"req":"status"}

-- getStatus :: Socket -> IO ()
-- getStatus sock = sendRequestToSharkd defaultSocketPath payload >> return ()
--   where
--     payload = object [
--         "req" .= toJSON ("status" :: String)
--       ]

-- {"req":"frames","filter":"frame.number<=20"}
-- getFrames
-- getFrames

