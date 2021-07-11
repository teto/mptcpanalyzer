-- {-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE PackageImports           #-}

module MptcpAnalyzer.Commands.List
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Types
import "mptcp-pm" Net.Tcp (TcpFlag(..))
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Stats
import MptcpAnalyzer.ArtificialFields
import Net.Tcp
import Net.Mptcp
import Net.Mptcp.Stats

import Frames.CSV
import Prelude hiding (log)
import Options.Applicative
import Frames
import qualified Frames as F
import qualified Frames.InCore as F
import Control.Lens hiding (argument)
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import qualified Polysemy.State as P
import Polysemy.Trace as P
import qualified Polysemy.Embed as P
import Data.Either (fromRight)
import Data.List (intercalate)
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import qualified Data.Map as Map

piListTcpOpts ::  ParserInfo CommandArgs
piListTcpOpts = info (
   ArgsListTcpConnections <$> parserList <**> helper)
  ( progDesc "List subflows of an MPTCP connection"
  )
  where
    parserList = switch (long "detailed" <> help "detail connections")

piTcpSummaryOpts :: ParserInfo CommandArgs
piTcpSummaryOpts = info (
   piTcpSummary <**> helper)
  ( progDesc "Detail a specific TCP connection"
    <> footer "Example: summary 0"
  )
  where
    piTcpSummary :: Parser CommandArgs
    piTcpSummary = ArgsParserSummary <$> switch
              ( long "full"
            <> help "Print details for each subflow" )
          <*> argument readStreamId (
              metavar "STREAM_ID"
              <> help "Stream Id (tcp.stream)"
              -- TODO pass a default
              )



piMptcpSummaryOpts :: ParserInfo CommandArgs
piMptcpSummaryOpts = info (
   piMptcpSummary <**> helper)
  ( progDesc "Detail a specific TCP connection"
  <> footer "mptcp-summary 0"
  )
  where
    piMptcpSummary :: Parser CommandArgs
    piMptcpSummary = ArgsMptcpSummary <$> switch
              ( long "full"
            <> help "Print details for each subflow" )
          <*> argument readStreamId (
              metavar "STREAM_ID"
              <> help "Stream Id (mptcp.stream)"
              -- TODO pass a default
              )

{-| Show a list of all connections
8 tcp connection(s)
  tcp.stream 0: 10.0.0.1:33782 -> 10.0.0.2:05201
  tcp.stream 1: 10.0.0.1:33784 -> 10.0.0.2:05201
  tcp.stream 2: 10.0.0.1:54595 -> 11.0.0.2:05201
  tcp.stream 3: 10.0.0.1:57491 -> 11.0.0.2:05201
  tcp.stream 4: 11.0.0.1:59555 -> 11.0.0.2:05201
  tcp.stream 5: 11.0.0.1:50077 -> 11.0.0.2:05201
  tcp.stream 6: 11.0.0.1:35589 -> 10.0.0.2:05201
  tcp.stream 7: 11.0.0.1:50007 -> 10.0.0.2:05201
-}
cmdListTcpConnections ::
  (Members '[Log, P.Trace, P.State MyState, Cache, Embed IO] r)
  => Bool -- ^ detailed
  -> Sem r RetCode
cmdListTcpConnections listDetailed = do
    -- TODO this part should be extracted so that
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> do
        trace "please load a pcap first"
        return CMD.Continue
      Just frame -> do
        let tcpStreams = getTcpStreams frame
        let streamIdList = if listDetailed then [] else tcpStreams
        -- log $ "Number of rows " ++ show (frameLength frame)
        P.trace $ "Number of TCP connections " ++ show (length tcpStreams)
        -- TODO use a trace there
        mapM_ (P.trace . describeConnection) streamIdList
        return CMD.Continue
        where
          describeConnection streamId = 
            case buildTcpConnectionFromStreamId frame streamId of
              Left msg -> msg
              -- addTcpDestToFrame 
              Right aframe -> showConnection (ffCon aframe)


{-| Display statistics for the connection:
throughput/goodput

detailed
-}
cmdTcpSummary :: ( Members '[Log, P.Trace, P.State MyState, Cache, Embed IO] r)
  => StreamId Tcp
  -> Bool
  -> Sem r RetCode
cmdTcpSummary streamId detailed = do
    state <- P.get
    let loadedPcap = view loadedFile state
    case loadedPcap of
      Nothing -> trace ("please load a pcap first" :: String) >> return CMD.Continue
      Just frame -> case buildTcpConnectionFromStreamId frame streamId of
        Left msg -> return $ CMD.Error msg
        Right aframe -> do
          -- let _tcpstreams = getTcpStreams frame
          P.trace $ showConnection (ffCon aframe)
          Log.info $ "Number of rows "  <> tshow (frameLength $ ffFrame aframe)
          if detailed
          then do
            res <- showStats aframe RoleServer
            P.trace res
            res2 <- showStats aframe RoleClient
            P.trace res2
          else
            pure ()
          -- log $ "Number of SYN packets " ++ (fmap  )
          return CMD.Continue
          -- where
          --     -- aframe = buildTcpConnectionFromStreamId frame streamId
          --     -- forwardStats = showStats RoleServer
          --     showStats direction = let
          --         aframeWithDest = addTcpDestinationsToAFrame aframe
          --         tcpStats = getTcpStats aframeWithDest direction
          --       in do
          --         showTcpStats tcpStats
          --         P.embed $ writeCSV "debug.csv" (ffFrame aframeWithDest)

-- |just
showStats :: ( Members '[Log, P.Trace, P.State MyState, Cache, Embed IO] r)
  => FrameFiltered TcpConnection Packet
  -> ConnectionRole
  -> Sem r String
showStats aframe dest = let
    aframeWithDest = addTcpDestinationsToAFrame aframe
    tcpStats = getTcpStats aframeWithDest dest

    destFrame = F.filterFrame (\x -> x ^. tcpDest == dest) (ffFrame aframeWithDest)

  in do
    P.embed $ writeDSV defaultParserOptions ("debug-" ++ show dest ++ ".csv") destFrame
    return $ showTcpStats tcpStats ++ "   (" ++ show (frameLength destFrame) ++ " packets)"


showTcpStats :: TcpUnidirectionalStats -> String
showTcpStats s =
                  "- transferred " ++ show (tusSndNext s - tusMinSeq s + 1 + tusReinjectedBytes s)  ++ " bytes "
                  ++ " over " ++ show (tusEndTime s - tusStartTime s) ++ "s: "
                  ++ " Throughput " ++ show (getThroughput s) ++ "b/s"


{-
Returns something
mptcp stream 0 transferred 469.0 Bytes over 45.831181 sec(456.0 Bytes per second) towards Server.
tcpstream 0 transferred 460.0 Bytes out of 469.0 Bytes, accounting for 98.08%
tcpstream 2 transferred 9.0 Bytes out of 469.0 Bytes, accounting for 1.92%
tcpstream 4 transferred 0.0 Bytes out of 469.0 Bytes, accounting for 0.00%
tcpstream 6 transferred 0.0 Bytes out of 469.0 Bytes, accounting for 0.00%
-}
showMptcpStats :: MptcpUnidirectionalStats -> String
showMptcpStats s = " Mptcp stats towards " ++ show (musDirection s) ++ " :\n"
    ++ "- Duration " ++ show (getMptcpStatsDuration s) ++ "\n"
    -- getMptcpGoodput
    ++ "- Goodput " ++ show (getMptcpGoodput s)
    ++ "<TODO>\n"
    ++ "Applicative Bytes : " ++ show (musApplicativeBytes s) ++ "\n"
    ++ "Subflow stats:\n"
    ++ intercalate "\n" (map showSubflowStats (Map.toList $ musSubflowStats s))
    where
      -- ++ show (tusStreamId)
      showSubflowStats (sf, sfStats) = let
          tcpStats = tssStats sfStats
          seqRange = getTcpSeqRange tcpStats
          totalApplicationBytes = musApplicativeBytes s
        in "stream " ++ show (conTcpStreamId (sfConn sf))
          ++ ": transferred " ++ show seqRange ++ " out of " ++ show totalApplicationBytes
          ++ " between "
          ++ show (tusStartTime tcpStats) ++ " end time: " ++ show (tusEndTime $ tssStats sfStats)
          ++ " , accouting for " ++ show (seqRange / fromIntegral totalApplicationBytes) ++ " %"

{-
Returns:
mptcp stream 0 transferred 308.0 Bytes over 45.658558 sec(308.0 Bytes per second) towards Client.
tcpstream 0 transferred 308.0 Bytes out of 308.0 Bytes, accounting for 100.00%
tcpstream 2 transferred 0.0 Bytes out of 308.0 Bytes, accounting for 0.00%
tcpstream 6 transferred 0.0 Bytes out of 308.0 Bytes, accounting for 0.00%
mptcp stream 0 transferred 469.0 Bytes over 45.831181 sec(456.0 Bytes per second) towards Server.
tcpstream 0 transferred 460.0 Bytes out of 469.0 Bytes, accounting for 98.08%
tcpstream 2 transferred 9.0 Bytes out of 469.0 Bytes, accounting for 1.92%
tcpstream 4 transferred 0.0 Bytes out of 469.0 Bytes, accounting for 0.00%
tcpstream 6 transferred 0.0 Bytes out of 469.0 Bytes, accounting for 0.00%
-}
cmdMptcpSummary :: (Members '[Log, P.Trace, P.State MyState, Cache, Embed IO] r)
  => StreamId Mptcp
  -> Bool
  -> Sem r RetCode
cmdMptcpSummary streamId detailed = do
  state <- P.get
  case view loadedFile state of
    Nothing -> trace ("please load a pcap first" :: String) >> return CMD.Continue
    Just frame -> case buildMptcpConnectionFromStreamId frame streamId of
      Left msg -> return $ CMD.Error msg
      Right aframe -> do
        let
          -- addTcpDestinationsToAFrame
          -- aframeWithDest = addTcpDestinationsToAFrame aframe

        -- let _tcpstreams = getTcpStreams frame
        -- TODO we need to add MptcpDest
        let mptcpStatsClient = getMptcpStats aframe RoleClient
        let mptcpStatsServer = getMptcpStats aframe RoleServer

        P.trace $ showConnection (ffCon aframe)
        Log.debug $ "Number of rows " <> tshow (frameLength frame)
        if detailed
        then
          -- RoleServer
          trace $ showMptcpStats mptcpStatsClient
          -- trace $ showMptcpStats mptcpStatsServer
        else
          pure ()
        return CMD.Continue
