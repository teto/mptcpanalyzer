{-# LANGUAGE ScopedTypeVariables #-}
module Utils (
  loadAFrame
  , loadPcapIntoFrameNoCache
)
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import Net.Tcp.Connection
import Tshark.Main
import MptcpAnalyzer.ArtificialFields

import Polysemy (Final, Members, Sem, runFinal)
import qualified Polysemy as P
import qualified Polysemy.Embed as P
import qualified Polysemy.IO as P
import qualified Polysemy.Internal as P
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Polysemy.Log.Colog (interpretLogStdout)
import MptcpAnalyzer.Loader (loadPcapIntoFrame)
import qualified Frames.InCore
import qualified Frames.CSV
import Frames (ColumnHeaders, ElField, FrameRec)
import MptcpAnalyzer.Cache (CacheConfig(..))
import Control.Monad.IO.Class (liftIO)
import Distribution.Simple.Utils
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

loadPcapIntoFrameNoCache :: (
    Frames.InCore.RecVec a
    , Frames.CSV.ReadRec a
    , ColumnHeaders a
    -- , V.RecMapMethod Show ElField a
    -- , V.RecordToList a
   )
    => TsharkParams
    -> FilePath
    -> IO (Either String (FrameRec a))
loadPcapIntoFrameNoCache params path = do 
  (tempPath , exitCode, stdErr) <- liftIO $ do
    withTempFileEx opts "/tmp" "mptcp.csv" $ \tmpPath handle ->
      exportToCsv params path handle
  -- return (tmpPath, exitCode, herr)
  if exitCode == ExitSuccess
  then
    return $ liftIO $ loadRows tempPath
  else
    return $  Left "Error happened " <> tshow exitCode <> "\n" <> tshow stdErr
  where
    opts :: TempFileOptions
    opts = TempFileOptions True



loadAFrame :: FilePath -> IO (FrameFiltered TcpConnection Packet)
loadAFrame = loadAFrameWithOpts defaultTsharkPrefs

loadAFrameWithOpts :: TsharkParams -> FilePath -> IO (FrameFiltered TcpConnection Packet)
loadAFrameWithOpts tsharkParams path = do
  frame1 <- loadPcapIntoFrameNoCache tsharkParams path

  (aframe :: FrameFiltered TcpConnection Packet) <- case buildFrameFromStreamId (fromRight (error "should not happen") frame1) (StreamId 0) of
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

