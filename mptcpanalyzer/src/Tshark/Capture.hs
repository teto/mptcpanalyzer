{-# LANGUAGE CPP #-}
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

-- mptcpanalyzer imports
import Net.Tcp.Connection
import Net.Tcp.Constants
import MptcpAnalyzer.Stream (StreamIdMptcp)
import Net.Mptcp.Connection
import Tshark.Live
import MptcpAnalyzer.Types
import Tshark.Main (csvDelimiter, defaultTsharkPrefs)
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.ArtificialFields
import Net.Tcp.Stats (getTcpStatsFromAFrame)
import Net.Mptcp.Stats

import Control.Monad.State (MonadState(get), StateT, gets, modify')
import qualified Data.Map.Strict as Map
import GHC.IO.Handle
import Pipes (Effect)
import Frames
import qualified Data.Text as T
import Frames.CSV (columnSeparator, ReadRec, ParserOptions, readRow, defaultParser)
import qualified Pipes as P
import qualified Pipes.Parse as P
import qualified Pipes.Prelude as P
import Pipes ((>->))
import Pipes hiding (Proxy)
import Debug.Trace (trace, traceShow, traceShowId)
import System.Console.ANSI
import Data.Vinyl.Functor (getCompose)
import qualified Control.Foldl                 as Foldl
import Control.Lens ((^.), (.~))
import qualified Data.Set as Set
import Data.Maybe (fromJust)
import Data.Either (rights)
import Control.Arrow (first)
import qualified Data.Foldable as F
import qualified Frames as F
import qualified Frames.InCore as F



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
      _ <- liftIO $ putStrLn "newLine"

      -- (frame ::  FrameRec HostCols) <- lift ( inCoreAoS (pipeLines (try. T.hGetLine) hout  >-> pipeTableEitherOpt popts >-> P.map fromEither ))
      -- let x2 :: Text = "1633468309.759952583|eno1|2a01:cb14:11ac:8200:542:7cd1:4615:5e05||2606:4700:10::6814:14ec|||||||||||127|||21.118721618||794|1481|51210|0x00000018|31||3300|443|3||"
      (frame :: FrameRec HostCols) <- liftIO $ inCoreAoS (yield (T.pack x) >-> pipeTableEitherOpt' popts >-> P.map fromEither )
      -- showFrame [csvDelimiter defaultTsharkPrefs] frame
      -- liftIO $ putStrLn $ showFrame [csvDelimiter defaultTsharkPrefs] frame
      let frameWithDest = addTcpDestinationsToAFrame (FrameTcp (lsConnection lsConfig) frame)

      -- stFrame <- gets lsFrame
      modify' (updateTcpStats frameWithDest)
      -- liftIO $ cursorUp 1
      liveStats <- get
      let output = showLiveStatsTcp liveStats
      liftIO $ cursorUpLine $ (+) 1 (Prelude.length $ T.lines output)
      liftIO clearFromCursorToScreenEnd
      liftIO $ (putStrLn . T.unpack) output

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

    -- updateStatsFrame :: FrameRec HostCols -> LiveStatsTcp -> LiveStatsTcp
    -- updateStatsFrame frame lstats = foldl updateStats lstats frame
    updateTcpStats frameWithDest tstats = tstats <> genLiveStatsTcp frameWithDest

    recEither = rtraverse getCompose

updateMptcpStats ::
  (
   -- TcpDest F.∈ rs
  MptcpDsn F.∈ rs, TcpSeq F.∈ rs, IpDest F.∈ rs, IpSource F.∈ rs
  , TcpLen F.∈ rs
  , PacketId F.∈ rs
  , TcpDestPort F.∈ rs, MptcpRecvToken F.∈ rs
  , TcpFlags F.∈ rs, TcpSrcPort F.∈ rs, TcpStream F.∈ rs, RelTime F.∈ rs
  , rs F.⊆ HostCols
  , F.RecVec rs
  )
  => FrameFiltered MptcpConnection (F.Record rs)
updateMptcpStats = undefined

-- | Display live update of MPTCP stats
-- Contrary to TCP we have to filter on the master subflow but as we can't update the filter as we discover
-- the subflows, we configure tshark to capture all MPTCP traffic and filter it in the application
-- 1/ first we need to find the master subflow
tsharkLoopMptcp :: LiveStatsConfig -> Handle -> Effect (StateT LiveStatsMptcp IO) ()
tsharkLoopMptcp config hout = do
  -- hSetBuffering hout LineBuffering
  -- ls <- for (tsharkProducer hout) $ \x -> do
  ls <- for (P.fromHandle hout) $ \x -> do

      -- (frame ::  FrameRec HostCols) <- lift ( inCoreAoS (pipeLines (try. T.hGetLine) hout  >-> pipeTableEitherOpt popts >-> P.map fromEither ))
      -- let x2 :: Text = "1633468309.759952583|eno1|2a01:cb14:11ac:8200:542:7cd1:4615:5e05||2606:4700:10::6814:14ec|||||||||||127|||21.118721618||794|1481|51210|0x00000018|31||3300|443|3||"
      (frame :: FrameRec HostCols) <- liftIO $ inCoreAoS (yield (T.pack x) >-> pipeTableEitherOpt' popts >-> P.map fromEither )
      -- showFrame [csvDelimiter defaultTsharkPrefs] frame
      -- liftIO $ putStrLn $ showFrame [csvDelimiter defaultTsharkPrefs] frame
      -- if we have no master subflow yet, we should check against it
      -- so now we should
      mptcpstats <- gets _lsmStats

      -- TODO should be a fmap considering the complexity
      modify' (updateStatsFrame frame)
      -- liftIO $ cursorUp 1
      liveStatsMptcp <- get
      -- showLiveStatsTcp liveStats
      let output = showLiveStatsMptcp liveStatsMptcp

      -- liftIO $ cursorUpLine $ (+) 1 (Prelude.length $ T.lines output)
      liftIO clearFromCursorToScreenEnd
      liftIO $ (putStrLn . T.unpack) output
      -- liftIO $ putStrLn $ "length " ++ show (frameLength stFrame)
      -- lift $ hPutStrLn stdout "test"
      -- return liveStatsMptcp

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
    updateStatsFrame :: FrameRec HostCols -> LiveStatsMptcp -> LiveStatsMptcp
    updateStatsFrame frame lstats = foldl updateStats lstats frame

    updateStats :: LiveStatsMptcp -> Record HostCols -> LiveStatsMptcp
    -- case where the master subflow was already identified
    updateStats lstats@(LiveStatsMptcp (Just main) _ _ subflows stats _) row =
      case mbSubflow of
        -- Not a registered subflow yet
        Nothing -> case row ^. mptcpRecvToken of
          Nothing ->
#ifdef DEBUG_CAPTURE
            trace "unknown subflow: No rcv token"
#endif
            lstats

          Just rcvToken -> let
              subflow = buildSubflowFromRecord row
            in
#ifdef DEBUG_CAPTURE
              trace "Rcv token received"
#endif
              (
              -- if token of client then subflow initiated by server
              if tokenBelongToConnection rcvToken main then
                lstats {
                  master =
#ifdef DEBUG_CAPTURE
                      trace ("Adding new subflow " ++ show subflow)
#endif
                      (Just (mptcpConnAddSubflow main subflow))

                }
              else
#ifdef DEBUG_CAPTURE
                trace ("ignoring flow " ++ show subflow)
#endif
                lstats
              )
        Just subflowStats ->
          case getSubflowFromStreamId main (row ^. tcpStream) of
            Nothing -> error "Could not find the subflow :s "
            Just subflow -> let
              -- TODO update tcp stats for th
              -- TODO change connection staths when seeing dataFin
              -- TODO update subflow stats and mptcp stats
                -- subflow = master
                tcpAframe :: FrameFiltered TcpConnection Packet
                tcpAframe =  FrameTcp (connection subflow) frame

                newMptcpStats :: LiveStats MptcpUnidirectionalStats Packet
                newMptcpStats = genLiveStatsMptcp mptcpAframe

                subflowUpdatedStats :: LiveStatsTcp
                subflowUpdatedStats = genLiveStatsTcp (addTcpDestinationsToAFrame tcpAframe)
              in
                -- case row ^. mptcpDataFin of
                --   Just val ->
-- #ifdef DEBUG_CAPTURE
                --     trace ("DATAFIN detected: " ++ show val)
-- #endif
                --     lstats {
                --       _lsmFinished = True
                --     }
                --   Nothing ->
#ifdef DEBUG_CAPTURE
                    trace ("known subflow: " ++ show subflow ++ " update stats")
#endif
                    (lstats {
                        -- TODO we should have stats in both direction !
                        -- _lsmStats = (lstats ^. lsmStats) <> newMptcpStats
                        _lsmStats = (lstats ^. lsmStats) <> newMptcpStats
                      , _lsmSubflows = Map.insert (row ^. tcpStream) (subflowStats <> subflowUpdatedStats) (lstats ^. lsmSubflows)
                    })
      where
        tuple = (buildTcpConnectionTupleFromRecord row)

        mptcpAframe :: FrameFiltered MptcpConnection Packet
        mptcpAframe =  FrameTcp main frame

        frame :: FrameRec HostCols
        frame = boxedFrame [row]
        mbSubflow = Map.lookup (row ^. tcpStream) (_lsmSubflows lstats)


    updateStats lstats@(LiveStatsMptcp Nothing (Just clientCfg) (Just serverCfg)  _subflows stats _) row = error "should not happen"

      -- in updateStats newStats row
    -- attempts to fetch client mptcp key/token from the initial syn (mptcp version 0)
    updateStats lstats@(LiveStatsMptcp Nothing _ _ _ stats _) row =
      -- synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
        if hasClientKey then
            -- streamPackets = filterFrame (\x -> x ^. mptcpStream == mympconStreamId) frame
            -- subflows = map (buildSubflowFromTcpStreamId frame) (getTcpStreams streamPackets)
#ifdef DEBUG_CAPTURE
            trace "SYN FOUND! retreiving client key"
#endif
            lstats {
                client = mptcpConfig
              , master = finalizeLiveStatsMptcp mptcpConfig lstats.server
              , _lsmSubflows = Map.singleton (row ^. tcpStream) (genLiveStatsTcp (FrameTcp (connection subflow) mempty))
              -- Set.fromList $ map ffCon (rights subflows)
              }
        else if isSynAck then
          -- lstats & set (traceShowId mptcpConfig)
#ifdef DEBUG_CAPTURE
              trace "SYNACK FOUND! retreiving server key"
#endif
              lstats {
                server = mptcpConfig
              , master = finalizeLiveStatsMptcp (client lstats) mptcpConfig
              }
        else
#ifdef DEBUG_CAPTURE
          trace "No syn\n"
#endif
          lstats
      where
        tuple = (buildTcpConnectionTupleFromRecord row)
        -- tcpAframe = buildA
        -- TcpFlagSyn `elem` (row ^. tcpFlags) &&
        hasClientKey = (row ^. mptcpSendKey ) /= Nothing && lsConnection config == tcpConnectionFromOriented tuple
        isSynAck = TcpFlagSyn `elem` (row ^. tcpFlags) &&  TcpFlagAck `elem` (row ^. tcpFlags)
                  && lsConnection config == tcpConnectionFromOriented (reverseTcpConnectionTuple tuple)
        mptcpConfig = genMptcpEndpointConfigFromRow row
        subflow :: MptcpSubflow
        subflow = (MptcpSubflow  (buildTcpConnectionFromRecord row) Nothing Nothing 0 0 Nothing)
        mympconStreamId :: Maybe StreamIdMptcp
        mympconStreamId =  row ^. mptcpStream
        finalizeLiveStatsMptcp :: Maybe MptcpEndpointConfiguration -> Maybe MptcpEndpointConfiguration -> Maybe MptcpConnection
        finalizeLiveStatsMptcp mclientCfg mserverCfg = case (mclientCfg, mserverCfg) of
          (Just clientCfg, Just serverCfg) ->
#ifdef DEBUG_CAPTURE
            trace "FINALIZING MPTCP connection"
#endif
            (Just $ MptcpConnection {
                -- get it from map.singleton
                mpconStreamId = fromJust $ mympconStreamId
              -- fromJust $ synAckPacket ^. mptcpSendKey
              , serverConfig = serverCfg
              , clientConfig = clientCfg
              -- , mptcpNegotiatedVersion = mptcpVersion (serverCfg) -- TODO fix
              -- , mpconSubflows = Set.fromList $ map ffCon (rights subflows)
              , subflows = Set.singleton subflow
            })
          _ -> Nothing
