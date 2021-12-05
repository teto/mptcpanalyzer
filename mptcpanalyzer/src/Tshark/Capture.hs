{-
Module:  Tshark.Capture
Description :  Description
Maintainer  : matt
Portability : Linux
-}
module Tshark.Capture
-- (
--    tsharkLoop
-- )
where

import Control.Monad.State (MonadState(get), StateT, gets, modify')

import GHC.IO.Handle
import Pipes (Effect)
import Frames
import Tshark.Live
import MptcpAnalyzer.Types
import Data.Text as T
import Frames.CSV (columnSeparator, ReadRec, ParserOptions, readRow, defaultParser)
import qualified Pipes as P
import qualified Pipes.Parse as P
import qualified Pipes.Prelude as P
import Pipes ((>->))
import Pipes hiding (Proxy)
import Tshark.Main (csvDelimiter, defaultTsharkPrefs)
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.ArtificialFields
import Net.Tcp (getTcpStats)

import Debug.Trace (trace, traceShow, traceShowId)
import System.Console.ANSI
import Data.Vinyl.Functor (getCompose)
import Net.Tcp.Connection
import qualified Control.Foldl                 as Foldl
import Net.Tcp.Constants
import Control.Lens ((^.))


-- copy/pasted
pipeTableEitherOpt' :: (Monad m, ReadRec rs)
                   => ParserOptions
                   -> P.Pipe T.Text (Rec (Either T.Text :. ElField) rs) m ()
pipeTableEitherOpt' opts = do
  -- when (isNothing (headerOverride opts)) (() <$ P.await)
  P.map (readRow opts)

-- produceFrameChunks
-- inCoreAoS
-- --capture-comment
-- TODO return the frame/ stats
tsharkLoopTcp :: LiveStatsConfig -> Handle -> Effect (StateT (LiveStatsTcp) IO) ()
tsharkLoopTcp lsConfig hout = do
  ls <- for (P.fromHandle hout) $ \x -> do

      -- (frame ::  FrameRec HostCols) <- lift ( inCoreAoS (pipeLines (try. T.hGetLine) hout  >-> pipeTableEitherOpt popts >-> P.map fromEither ))
      -- let x2 :: Text = "1633468309.759952583|eno1|2a01:cb14:11ac:8200:542:7cd1:4615:5e05||2606:4700:10::6814:14ec|||||||||||127|||21.118721618||794|1481|51210|0x00000018|31||3300|443|3||"
      (frame :: FrameRec HostCols) <- liftIO $ inCoreAoS (yield (T.pack x) >-> pipeTableEitherOpt' popts >-> P.map fromEither )
      -- showFrame [csvDelimiter defaultTsharkPrefs] frame
      liftIO $ putStrLn $ showFrame [csvDelimiter defaultTsharkPrefs] frame
      stFrame <- gets lsFrame
      modify' (updateState frame)
      -- liftIO $ cursorUp 1
      liveStats <- get
      -- showLiveStatsTcp liveStats
      let output = showLiveStatsTcp liveStats

      -- liftIO $ cursorUpLine $ (+) 1 (Prelude.length $ T.lines output)
      liftIO clearFromCursorToScreenEnd
      liftIO $ (putStrLn . T.unpack) output
      -- liftIO $ putStrLn $ "length " ++ show (frameLength stFrame)
      -- lift $ hPutStrLn stdout "test"

  -- liftIO $ (putStrLn . T.unpack . showLiveStatsTcp) ls
  pure ls

  where
    -- tokenize = tokenizeRow popts
    popts = defaultParser {
          columnSeparator = T.pack $ [csvDelimiter defaultTsharkPrefs]
        }
    fromEither x = case recEither x of
      Left _txt -> error ( "eitherProcessed failure : " ++ T.unpack _txt)
      Right pkt -> pkt

    recEither = rtraverse getCompose
    updateState :: FrameRec HostCols -> LiveStatsTcp -> LiveStatsTcp
    updateState frame stats = let
            frameWithDest = addTcpDestinationsToAFrame (FrameTcp (lsConnection lsConfig) frame)
            forwardFrameWithDest = getTcpStats frameWithDest RoleServer
            backwardFrameWithDest = getTcpStats frameWithDest RoleClient
        in (stats {
        lsPackets = lsPackets stats + 1
        , lsFrame = (lsFrame stats)  <> frame
        , lsForwardStats = let
            merged = (lsForwardStats stats) <> trace ("FRAMEWITH DEST\n" ++ showFrame [csvDelimiter defaultTsharkPrefs] (ffFrame frameWithDest) ++ "\n " ++ show forwardFrameWithDest) forwardFrameWithDest
            in traceShowId merged
        , lsBackwardStats = (lsBackwardStats stats) <> traceShowId backwardFrameWithDest
        })

-- Tricky function:
-- Contrary to TCP we have to filter on the master subflow but as we can't update the filter as we discover
-- the subflows, we configure tshark to capture all MPTCP traffic and filter it in the application
-- 1/ first we need to find the master subflow
tsharkLoopMptcp :: LiveStatsConfig -> Handle -> Effect (StateT LiveStatsMptcp IO) ()
tsharkLoopMptcp config hout = do
  -- hSetBuffering stdout NoBuffering
  -- ls <- for (tsharkProducer hout) $ \x -> do
  ls <- for (P.fromHandle hout) $ \x -> do

      -- (frame ::  FrameRec HostCols) <- lift ( inCoreAoS (pipeLines (try. T.hGetLine) hout  >-> pipeTableEitherOpt popts >-> P.map fromEither ))
      -- let x2 :: Text = "1633468309.759952583|eno1|2a01:cb14:11ac:8200:542:7cd1:4615:5e05||2606:4700:10::6814:14ec|||||||||||127|||21.118721618||794|1481|51210|0x00000018|31||3300|443|3||"
      (frame :: FrameRec HostCols) <- liftIO $ inCoreAoS (yield (T.pack x) >-> pipeTableEitherOpt' popts >-> P.map fromEither )
      -- showFrame [csvDelimiter defaultTsharkPrefs] frame
      liftIO $ putStrLn $ showFrame [csvDelimiter defaultTsharkPrefs] frame
      -- if we have no master subflow yet, we should check against it
      -- so now we should
      mptcpstats <- gets lsmStats
      modify' (updateStats frame)
      -- liftIO $ cursorUp 1
      liveStatsMptcp <- get
      -- showLiveStatsTcp liveStats
      let output = showLiveStatsMptcp liveStatsMptcp

      -- liftIO $ cursorUpLine $ (+) 1 (Prelude.length $ T.lines output)
      liftIO clearFromCursorToScreenEnd
      liftIO $ (putStrLn . T.unpack) output
      -- liftIO $ putStrLn $ "length " ++ show (frameLength stFrame)
      -- lift $ hPutStrLn stdout "test"

  -- liftIO $ (putStrLn . T.unpack . showLiveStatsTcp) ls
  pure ls

  where
    -- tokenize = tokenizeRow popts
    popts = defaultParser {
          columnSeparator = T.pack $ [csvDelimiter defaultTsharkPrefs]
        }
    fromEither x = case recEither x of
      Left _txt -> error ( "eitherProcessed failure : " ++ T.unpack _txt)
      Right pkt -> pkt

    recEither = rtraverse getCompose


    -- expects a frame and a LiveStatsMptcp
    updateStats :: FrameRec HostCols -> LiveStatsMptcp -> LiveStatsMptcp
    updateStats frame lstats@(LiveStatsMptcp (Just master) subflows stats) = lstats
    -- looking for the tokens
    updateStats frame lstats@(LiveStatsMptcp Nothing subflows stats) = 
      -- synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
      let
        synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags) && lsConnection config == buildTcpConnectionFromRecord x) frame
      in
        lstats

      -- lstats
      --   frameWithDest = addTcpDestinationsToAFrame (FrameTcp (lsConnection stats) frame)
      --   forwardFrameWithDest = getTcpStats frameWithDest RoleServer
      --   backwardFrameWithDest = getTcpStats frameWithDest RoleClient
      --   in stats {
      --   lsPackets = lsPackets stats + 1
      --   , lsFrame = (lsFrame stats)  <> frame
      --   , lsForwardStats = let
      --       merged = (lsForwardStats stats) <> trace ("FRAMEWITH DEST\n" ++ showFrame [csvDelimiter defaultTsharkPrefs] (ffFrame frameWithDest) ++ "\n " ++ show forwardFrameWithDest) forwardFrameWithDest
      --       in traceShowId merged
      --   , lsBackwardStats = (lsBackwardStats stats) <> traceShowId backwardFrameWithDest
      --   })



