{-
Command to analyze reinjections

-}
module MptcpAnalyzer.Commands.Reinjections
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.List as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Merge
import MptcpAnalyzer.Stream
import MptcpAnalyzer.ArtificialFields
import Net.Mptcp

import Prelude hiding (log)
import Options.Applicative
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import Polysemy.Trace as P
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Data.Function (on)
import Data.List (sortBy, sortOn, intersperse, intercalate)
import Data.Either (rights, lefts)
import Frames
import Frames.CSV
import Frames.Rec
import Data.Maybe
import Control.Lens ((^.))
import Data.Foldable (toList)
import qualified Data.Foldable as F
import qualified Pipes as Pipes
import qualified Pipes.Prelude as Pipes
import Control.Lens hiding (argument)

import qualified Debug.Trace as D
import Control.Monad

piListReinjections :: ParserInfo CommandArgs
piListReinjections = info (
    (parserListReinjections )
    <**> helper)
  ( progDesc "List MPTCP reinjections"
  )
  where
    -- parserListReinjections :: Parser CommandArgs
    parserListReinjections =
          ArgsListReinjections <$>
          -- strArgument (
          --     metavar "PCAP1"
          --     <> help "File to analyze"
          -- )
          -- <*>
          argument readStreamId (
              metavar "TCP_STREAM"
              <> help "stream id to analyze"
          )

piQualifyReinjections :: ParserInfo CommandArgs
piQualifyReinjections = info (
    (parserQualifyReinjections) <**> helper)
  ( progDesc "Qualifies MPTCP reinjections"
  <> footer "analyze examples/client_2_redundant.pcapng 0 examples/server_2_redundant.pcapng 0"
  )


parserQualifyReinjections :: Parser CommandArgs
parserQualifyReinjections =
      ArgsQualifyReinjections
      <$> parserPcapMapping False
      <*> switch (
          long "verbose"
          <> help "Verbose or not"
      )

cmdListReinjections :: (Members '[Log, P.Trace, P.State MyState, Cache, Embed IO] r)
    => StreamId Mptcp
    -> Sem r RetCode
cmdListReinjections streamId = do
  state <- P.get
  let loadedPcap = view loadedFile state
  case loadedPcap of
    Nothing -> do
      trace "please load a pcap first"
      return CMD.Continue
    Just (frame :: FrameRec HostCols) -> do
      let
        reinjectedPacketsFrame = filterFrame (\x -> isJust $ x ^. reinjectionOf) frame
      -- log $ "Number of rows " ++ show (frameLength frame)
        outputs = fmap showReinjections reinjectedPacketsFrame
      -- P.embed $ putStrLn $ "Number of MPTCP connections " ++ show (length mptcpStreams)
      -- P.embed $ putStrLn $ show mptcpStreams
      P.trace $ intercalate "\n" (toList outputs)
      return CMD.Continue
      where
        -- packetid=757 (tcp.stream 1) is a reinjection of 1 packet(s):
        -- - packet 256 (tcp.stream 7)
        showReinjections row = "packetid=" ++ show (row ^. packetId) ++ " (tcp.stream " ++ show (row ^. tcpStream) ++ ")\n"
            -- TODO map over the list
            ++ intercalate "\n" ( map showReinjection (fromJust $ row ^. reinjectionOf))

        showReinjection reinjection = case toList $ filterFrame (\x -> x ^. packetId == reinjection) (frame) of
          [] -> error "did not find original packet"
          rows -> "- Reinjection of " ++ show reinjection ++ "(tcp.stream " ++ show ( (head rows)  ^. tcpStream) ++ ")"

-- Analyzes row of reinject packets
-- Compares arrival time of the first send of a segment with the
analyzeReinjection :: (FrameRec SenderReceiverCols) -> Record SenderReceiverCols -> Double
analyzeReinjection mergedFrame row =
  let
    -- a list of packetIds
    reinjectOf = fromJust (rgetField @SndReinjectionOf row)
    initialPktId = D.traceShowId $ head reinjectOf

    -- it is a frame

    originalPkt :: Record SenderReceiverCols
    originalPkt = let
          originalFrame = filterFrame (\x -> x ^. sndPacketId == initialPktId) mergedFrame
      in case frameLength (originalFrame) of
      0 -> error "empty frame"
      _ -> frameRow originalFrame 0

    origArrival, reinjArrival :: Double
    origArrival = rgetField @RcvRelTime originalPkt
    reinjArrival = rgetField @RcvRelTime originalPkt
    reinjPktId = row ^. sndPacketId

    delta = reinjArrival - origArrival
  in
    delta


{- Tries to distinguish between useful and useless reinjections
  Also tries to evalute the usefulness by providing a delta showing how much time
  the reinjection made the connection win or lose
-}
cmdQualifyReinjections ::
  Members '[
    Log
    , P.State MyState
    , Cache
    , P.Trace
    , Embed IO
    ] r
  => PcapMapping Mptcp
  -> [ConnectionRole]
  -> Bool
  -> Sem r RetCode
cmdQualifyReinjections (PcapMapping pcap1 streamId1 pcap2 streamId2) destinations verbose = do
  eframe1 <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap1 streamId1
  eframe2 <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap2 streamId2
  res <- case (eframe1, eframe2 ) of
    (Right aframe1, Right aframe2) -> do

          mergedRes <- mergeMptcpConnectionsFromKnownStreams aframe1 aframe2
          let
            -- mergedRes = mergeMptcpConnectionsFromKnownStreams' aframe1 aframe2
            reinjectedPacketsHost1 = filterFrame (\x -> isJust $ x ^. reinjectionOf) (ffFrame aframe1)
            reinjectedPacketsHost2 = filterFrame (\x -> isJust $ x ^. reinjectionOf) (ffFrame aframe2)

            -- mbRecs = map recMaybe mergedRes
            -- packets that could be mapped in both pcaps
            -- justRecs = catMaybes mbRecs
            myFrame = convertToSenderReceiver mergedRes

            reinjectedPacketsFrame = filterFrame (\x -> isJust $ x ^. sndReinjectionOf) myFrame

            -- loop over these reinjectpackets
            -- assume both were mapped

          -- Log.info $ "Result of the analysis; reinjections:"
            -- <> tshow (showReinjects justRecs)
          -- Log.debug $ "reinjectionsOf in host1 frame " <> tshow $ showFrame myFrame
          -- Log.debug $ "showing merged res" <> tshow (showMergedRes $ take 3 mergedRes)
          -- P.embed $ writeMergedPcap ("mergedRes-"  ++ ".csv") mergedRes
          trace $ "Size after conversion to sender/receiver " ++ show (frameLength myFrame) 
                  ++ "( " ++ show (length mergedRes) ++ ")"
          -- trace $ "Number of reinjected packets: " ++ show (frameLength reinjectedPacketsFrame)

          -- trace $ "Merged mptcp connection\nFrame size: " ++ show (frameLength reinjectedPacketsFrame)
                  -- ++ "\n" ++ showFrame "," reinjectedPacketsFrame
          forM_ destinations $ \x -> do
            qualifyReinjections myFrame (assignRoles aframe1 aframe2) x

          -- qualifyReinjections tempPath handle (getDests dest) (ffCon aframe1) mergedRes
          return CMD.Continue
    (Left err, _) -> return $ CMD.Error err
    (_, Left err) -> return $ CMD.Error err


  return CMD.Continue
    -- mergedPcap
    -- reinjectedPackets = filterFrame (sndReinjectionOf) (toFrame justRecs)

-- buildTcpConnectionFromSndRecord :: (
--   SndIpSource ∈ rs, SndIpDest ∈ rs, SndTcpSrcPort ∈ rs, SndTcpDestPort ∈ rs, SndTcpStream ∈ rs
--     -- rs ⊆ HostCols
--   )
--   => Record rs -> TcpConnection
-- buildTcpConnectionFromRecord r =
--   TcpConnection {
--     conTcpClientIp = r ^. sndIpSource
--     , conTcpServerIp = r ^. sndIpDest
--     , conTcpClientPort = r ^. sndTcpSrcPort
--     , conTcpServerPort = r ^. sndTcpDestPort
--     , conTcpStreamId = r ^. sndTcpStream
--   }


-- buildConnectionFromSndPacket :: Record SenderReceiverCols -> TcpConnection
-- buildConnectionFromSndPacket row -> 


-- | Returns (Client,Server)
-- kinbda hackish
assignRoles :: FrameFiltered MptcpConnection Packet -> FrameFiltered MptcpConnection Packet 
  -> (FrameFiltered MptcpConnection Packet , FrameFiltered MptcpConnection Packet)
assignRoles aframe1 aframe2 = 
  if delta > 0 then
    (aframe1, aframe2)
  else
    (aframe2, aframe1)
  where
    -- assume non empty
    firstRow1 = frameRow (ffFrame aframe1) 0
    firstRow2 = frameRow (ffFrame aframe2) 0

    delta :: Double
    delta = (firstRow2 ^. absTime) - (firstRow1 ^. absTime)

    -- selectDest :: ConnectionRole -> FrameRec MergedHostCols
    -- selectDest dest = (filterFrame (\x -> x ^. senderDest == dest) jframe)


-- TODO there should be a classification on a per mptcp basis
-- Here we should be able to tell who is the sender
qualifyReinjections :: Members '[
    Log, P.State MyState
    , Cache
    , P.Trace
    , Embed IO
    ] r
    => FrameRec SenderReceiverCols
    -- (Client, server) pcaps
    -> (FrameFiltered MptcpConnection Packet,FrameFiltered MptcpConnection Packet)
    -> ConnectionRole
    -> Sem r ()
qualifyReinjections frame (aframeH1, aframeH2) dest = do
    let
      -- "dest"frame
      dstFrame = filterFrame (\x -> x ^. senderDest == dest) frame
      -- mergedRes = mergeMptcpConnectionsFromKnownStreams' aframe1 aframe2
      -- reinjectedPacketsHost1 = filterFrame (\x -> isJust $ x ^. reinjectionOf) (ffFrame aframe1)
      -- reinjectedPacketsHost2 = filterFrame (\x -> isJust $ x ^. reinjectionOf) (ffFrame aframe2)
      reinjectedPacketsFrame = filterFrame (\x -> isJust $ x ^. sndReinjectionOf) dstFrame
      reinjects = fmap (analyzeReinjection frame) reinjectedPacketsFrame

    trace $ "Qualify reinjections for dests " ++ show dest
    P.embed $ writeDSV defaultParserOptions ("sndrcv-merged-" ++ show dest  ++ ".csv") dstFrame
    trace $ "Number of reinjected packets: " ++ show (frameLength reinjectedPacketsFrame)
    -- trace $ "Result of the analysis; reinjections:" ++ showReinjects reinjects
    forM_ reinjectedPacketsFrame $ \row -> do
      let
        reinjectOf = fromJust (rgetField @SndReinjectionOf row)
        hostType = rgetField @SenderHost row
        senderDest = rgetField @SenderDest row

        -- originalFrame = if senderDest == RoleClient then (ffFrame aframeH2) else (ffFrame aframeH1)
        originalFrame = frame

        -- should be only one
        originalPackets = filterFrame (\x -> x ^. sndPacketId == initialPktId) originalFrame

        -- ((frameRow originalPacket 0) ^. senderHost)
        hostBool = if frameLength originalPackets > 0 then show hostType else "unknown"

        -- TODO we want to find
        -- buildTcpConnectionFromSndRecord

        initialPktId = D.traceShowId $ head reinjectOf
        -- initialPktId = D.traceShowId $ head reinjectOf
      -- of packet id " ++ show initialPktId
      -- from host" ++ show hostType
      trace $ show (row ^. sndPacketId) ++ " is a reinjection of packet id " ++ show initialPktId
      trace $ "number of original packets " ++ show (frameLength originalPackets) ++ " Host " ++ show senderDest
      trace $ describeReinjection row originalPackets
      -- TODO check if pktId is available

    where
        showReinjects frame2 =
          -- unlines (intercalate sep (columnHeaders (Proxy :: Proxy (Record rs))) : rows)
          intercalate "," rows
          where
            rows = Pipes.toList (F.mapM_ (Pipes.yield . show ) frame2)

        describeReinjection reinjectedPacket originalPackets = case frameLength originalPackets of
          0 -> "No original packets found FISHY ?!"
          _otherwise -> let
                originalPacket = frameRow originalPackets 0
                reinjArrivalTime = reinjectedPacket ^. rcvAbsTime
                originalArrivalTime = originalPacket ^. rcvAbsTime
                reinj_delta = reinjArrivalTime - originalArrivalTime

            in
            if reinj_delta < 0 then
                "Efficient reinjection: latency gain: " ++ show reinj_delta

            else
              "Redundant reinjection : latency delta = " ++ show reinj_delta
              --

            --     # print("GOT A failed reinjection")
            --     df_all.loc[df_all[_sender("packetid")] == reinjection.packetid, "redundant"] = True
            --     #TODO set reinj_delta for reinjection.packetid
            -- else:
            --     # print("GOT a successful reinjection")
            --     pass

