module MptcpAnalyzer.Loader
where
import MptcpAnalyzer.Types
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Frame

import Prelude hiding (log)
import Control.Monad.Trans (liftIO)
import System.Exit (ExitCode(..))
-- import Colog.Polysemy (Log, log)
import Polysemy (Sem, Members, Embed)
import Polysemy.State as P
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import Frames
import Frames.CSV
import Net.Tcp
import Net.Mptcp
import qualified Frames.InCore

import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import qualified Data.Vinyl as V
import qualified Data.Vinyl.Class.Method as V


-- TODO return an Either or Maybe ?
-- return an either instead
loadPcapIntoFrame ::
    (Frames.InCore.RecVec a
    , Frames.CSV.ReadRec a
    , ColumnHeaders a
    , V.RecMapMethod Show ElField a, V.RecordToList a
    , Members [Log, Cache, Embed IO ] m)
    => TsharkParams
    -> FilePath
    -> Sem m (Either String (FrameRec a))
loadPcapIntoFrame params path = do
    Log.info $ "Start loading pcap " <> tshow path
    x <- getCache cacheId
    case x of
      Right frame -> do
          Log.debug $ tshow cacheId <> " in cache"
          return $ Right frame
      Left err -> do
          Log.debug $ "cache miss: " <> tshow  err
          Log.debug "Calling tshark"
          (tempPath , exitCode, stdErr) <- liftIO $ withTempFileEx opts "/tmp" "mptcp.csv" (exportToCsv params path)
          if exitCode == ExitSuccess
              then do
                Log.debug $ "exported to file " <> tshow tempPath
                frame <- liftIO $ loadRows tempPath
                Log.debug $ "Number of rows after loading " <> tshow (frameLength frame)
                cacheRes <- putCache cacheId frame
                -- use ifThenElse instead
                if cacheRes then
                  Log.info "Saved into cache"
                else
                  pure ()
                return $ Right frame
              else do
                Log.info $ "Error happened: " <> tshow exitCode
                Log.info $ tshow stdErr
                return $ Left stdErr

    where
      cacheId = CacheId [path] "" "csv"
      opts :: TempFileOptions
      opts = TempFileOptions True



-- buildTcpFrameFromFrame
-- \ Build a frame with only packets belonging to @streamId@
buildAFrameFromStreamIdTcp :: (Members [Log, Cache, Embed IO ] m)
    => TsharkParams
    -> FilePath
    -> StreamId Tcp
    -> Sem m (Either String (FrameFiltered TcpConnection Packet))
buildAFrameFromStreamIdTcp params pcapFilename streamId = do
    res <- loadPcapIntoFrame params pcapFilename
    return $ case res of
      Left err -> Left err
      Right frame -> buildTcpConnectionFromStreamId frame streamId

buildAFrameFromStreamIdMptcp :: (Members [Log, Cache, Embed IO ] m)
    => TsharkParams
    -> FilePath
    -> StreamId Mptcp
    -> Sem m (Either String (FrameFiltered MptcpConnection Packet))
buildAFrameFromStreamIdMptcp params pcapFilename streamId = do
  Log.debug  ("Building frame for mptcp stream " <> tshow streamId)
  res <- loadPcapIntoFrame params pcapFilename
  return $ case res of
    Left err -> Left err
    Right frame -> buildMptcpConnectionFromStreamId frame streamId
