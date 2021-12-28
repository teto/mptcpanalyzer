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
import System.Process hiding (runCommand)
import qualified Control.Exception as E
import Data.ByteString.Lazy (toStrict)


defaultSocketPath :: FilePath
defaultSocketPath = "/tmp/sharkd"


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

sendRequestToSharkd :: FilePath -> Value -> IO Socket
sendRequestToSharkd sockPath payload = do
  -- withFdSocket sock (setCloseOnExecIfNeeded)
  E.bracketOnError (openSocket addr) close $ \sock -> do
      setSocketOption sock ReuseAddr 1
      withFdSocket sock setCloseOnExecIfNeeded
      bind sock $ addrAddress addr
      sendAll sock (toStrict $ encode payload)
      -- listen sock 1024
      return sock
  where
    addr = defaultHints  { addrFamily = AF_UNIX, addrAddress = SockAddrUnix sockPath }
    -- sock = socket Stream 0

-- |
-- {"req":"load","file":"c:/traces/Contoso_01/web01/web01_00001_20161012151754.pcapng"}
loadFile :: FilePath -> FilePath -> IO ()
loadFile pcapPath sockPath = sendRequestToSharkd sockPath payload >> return ()
  where
    payload = object [
        "req" .= toJSON ("load" :: String)
      , "file" .= pcapPath
      ]


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
