{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Utils (
  loadAFrame
  -- , loadPcapIntoFrameNoCache
)
where

import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Types
import qualified MptcpAnalyzer.Utils.Text as T
import Net.Tcp.Connection
import Tshark.Main

import Control.Monad.IO.Class (liftIO)
import Data.Either (fromRight)
import Distribution.Simple.Utils
import Frames (ColumnHeaders, ElField, FrameRec)
import qualified Frames.CSV
import qualified Frames.InCore
import MptcpAnalyzer.Cache (CacheConfig(..))
import MptcpAnalyzer.Loader (loadPcapIntoFrame, loadPcapIntoFrameNoCache)
import Polysemy (Final, Members, Sem, runFinal)
import qualified Polysemy as P
import qualified Polysemy.Embed as P
import qualified Polysemy.IO as P
import qualified Polysemy.Internal as P
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Polysemy.Log.Colog (interpretLogStdout)
import System.Exit
cacheDisabledConfig :: CacheConfig
cacheDisabledConfig = CacheConfig {
    cacheFolder = "/tmp"
  , cacheEnabled = False
}

-- loadAFrame :: IO (FrameFiltered TcpConnection Packet)
-- loadAFrame = do

--   aframe <- P.runM
--     $ interpretLogStdout
--     $ runCache cacheDisabledConfig
--       runTests
--   return aframe
--   putStrLn "finished"

-- loadAFrame
--   (aframe :: FrameFiltered TcpConnection Packet) <- case buildFrameFromStreamId (fromRight (error "should not happen") eFrame1) (StreamId 0) of
--     Left err -> error err
--     Right aframe -> return aframe


loadAFrame :: FilePath -> StreamId Tcp -> IO (FrameFiltered TcpConnection Packet)
loadAFrame = loadAFrameWithOpts defaultTsharkPrefs

loadAFrameWithOpts :: TsharkParams -> FilePath -> StreamId Tcp -> IO (FrameFiltered TcpConnection Packet)
loadAFrameWithOpts tsharkParams path streamId = do
  frame1 <- loadPcapIntoFrameNoCache tsharkParams path

  (aframe :: FrameFiltered TcpConnection Packet) <- case buildFrameFromStreamId (fromRight (error "should not happen") frame1) streamId of
    Left err -> error err
    Right aframe -> return aframe

  return aframe

-- runTests :: (Members '[P.Embed IO, Log, Cache] r) => Sem r (FrameFiltered TcpConnection Packet)
-- runTests = do
--   -- :: Either String (Frame Packet)
--   frame1 <- loadPcapIntoFrame defaultTsharkPrefs "examples/client_2_cleaned.pcapng"

--   (aframe :: FrameFiltered TcpConnection Packet) <- case buildFrameFromStreamId (fromRight (error "should not happen") frame1) (StreamId 0) of
--     Left err -> error err
--     Right aframe -> return aframe

--   return aframe

