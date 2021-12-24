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
import Net.Tcp.Stats (getTcpStats)

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
import Control.Lens ((^.))
import qualified Data.Set as Set
import Data.Maybe (fromJust)
import Data.Either (rights)
import Control.Arrow (first)



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
  -- hSetBuffering hout LineBuffering
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
    updateStats lstats@(LiveStatsMptcp (Just master) _ _ subflows stats) row = 
      if row ^. mptcpRecvToken /= Nothing then
        trace "Master established" lstats
      else
        -- TODO
        lstats

    updateStats lstats@(LiveStatsMptcp Nothing (Just clientCfg) (Just serverCfg)  _subflows stats) row = error "should not happen"
      -- newStats = lstats {
      --   lsmMaster = trace "FINALIZING MPTCP connection" Just $ MptcpConnection {
      --           -- get it from map.singleton
      --           mptcpStreamId = fromJust $ myMptcpStreamId
      --         -- fromJust $ synAckPacket ^. mptcpSendKey
      --         , mptcpServerConfig = serverCfg
      --         , mptcpClientConfig = clientCfg
      --         -- , mptcpNegotiatedVersion = 0 -- ignore for now
      --         , mpconSubflows = Set.fromList $ map ffCon (rights subflows)
      --       }
      --     }

      -- in updateStats newStats row
    -- attempts to fetch client mptcp key/token from the initial syn (mptcp version 0)
    updateStats lstats@(LiveStatsMptcp Nothing _ _ _ stats) row =
      -- synPackets = filterFrame (\x -> TcpFlagSyn `elem` (x ^. tcpFlags)) streamPackets
        if hasClientKey then
            -- streamPackets = filterFrame (\x -> x ^. mptcpStream == myMptcpStreamId) frame
            -- subflows = map (buildSubflowFromTcpStreamId frame) (getTcpStreams streamPackets)
            trace "SYN FOUND! retreiving client key" lstats {
                lsmClient = traceShowId mptcpConfig
              , lsmMaster = finalizeLiveStatsMptcp mptcpConfig (lsmServer lstats)
              , lsmSubflows = Map.singleton subflow (mempty, mempty)
              -- Set.fromList $ map ffCon (rights subflows)
              }
        else if isSynAck then
              trace "SYNACK FOUND! retreiving server key" lstats {
                lsmServer = traceShowId mptcpConfig
              , lsmMaster = finalizeLiveStatsMptcp (lsmClient lstats) mptcpConfig
              }
        else
          trace "No syn\n" lstats
      where
        tuple = traceShowId (buildTcpConnectionTupleFromRecord row)
        -- TcpFlagSyn `elem` (row ^. tcpFlags) &&
        hasClientKey = (row ^. mptcpSendKey ) /= Nothing && lsConnection config == tcpConnectionfromOriented tuple
        isSynAck = TcpFlagSyn `elem` (row ^. tcpFlags) &&  TcpFlagAck `elem` (row ^. tcpFlags) 
                  && lsConnection config == tcpConnectionfromOriented (reverseTcpConnectionTuple tuple)
        mptcpConfig = genMptcpEndpointConfigFromRow row
        subflow :: MptcpSubflow
        subflow = (MptcpSubflow  (buildTcpConnectionFromRecord row) Nothing Nothing 0 0 Nothing)
        myMptcpStreamId :: Maybe StreamIdMptcp
        myMptcpStreamId =  row ^. mptcpStream
        finalizeLiveStatsMptcp :: Maybe MptcpEndpointConfiguration -> Maybe MptcpEndpointConfiguration -> Maybe MptcpConnection
        finalizeLiveStatsMptcp mclientCfg mserverCfg = case (mclientCfg, mserverCfg) of
          (Just clientCfg, Just serverCfg) ->
            trace "FINALIZING MPTCP connection" (Just $ MptcpConnection {
                -- get it from map.singleton
                mptcpStreamId = fromJust $ myMptcpStreamId
              -- fromJust $ synAckPacket ^. mptcpSendKey
              , mptcpServerConfig = serverCfg
              , mptcpClientConfig = clientCfg
              -- , mptcpNegotiatedVersion = mptcpVersion (serverCfg) -- TODO fix
              -- , mpconSubflows = Set.fromList $ map ffCon (rights subflows)
              , mpconSubflows = Set.singleton subflow
            })
          _ -> Nothing

    -- fetch server mptcp key/token from the syn/ack
    -- TODO at the end it should call itself ?
    -- updateStats frame lstats@(LiveStatsMptcp Nothing _clientCfg Nothing _subflows stats) =
    --   let
    --     synPacket = (frameRow synPackets 0)
    --     myMptcpStreamId :: Maybe StreamIdMptcp
    --     myMptcpStreamId =  synPacket ^. mptcpStream
    --     mptcpServerCfg = fromJust $ genMptcpEndpointConfigFromRow synPacket 
    --     matchConnection row = let
    --         tuple = traceShowId (buildTcpConnectionTupleFromRecord row)
    --       in
    --         TcpFlagSyn `elem` (row ^. tcpFlags) && lsConnection config == tcpConnectionfromOriented (reverseTcpConnectionTuple tuple)
    --     synPackets = filterFrame (matchConnection) frame
    --     streamPackets = filterFrame (\x -> x ^. mptcpStream == myMptcpStreamId) frame

    --     -- subflows shall be discovered along the way
    --     subflows = map (buildSubflowFromTcpStreamId frame) (getTcpStreams streamPackets)

    --   in
    --     case lsmClient lstats of
    --       Just clientConfig -> trace "FINALIZING MPTCP connection" lstats {
    --           lsmServer = Just mptcpServerCfg
    --         , lsmMaster = Just $ MptcpConnection {
    --             mptcpStreamId = fromJust $ myMptcpStreamId
    --           -- fromJust $ synAckPacket ^. mptcpSendKey
    --           , mptcpServerConfig = mptcpServerCfg
    --           , mptcpClientConfig = clientConfig
    --           , mpconSubflows = Set.fromList $ map ffCon (rights subflows)
    --         }
    --       }
    --       Nothing -> trace " still waiting for client config" lstats {
    --         lsmServer = Just mptcpServerCfg
    --       }

    -- fetch client mptcp key/token from the client answer to the syn/ack, in mptcp version 1
    -- updateStats lstats@(LiveStatsMptcp Nothing Nothing (Just serverConfig) _ stats) row = lstats
