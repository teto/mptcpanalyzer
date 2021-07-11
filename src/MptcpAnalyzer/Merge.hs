{-
Module      : MptcpAnalyzer.Merge
Description : Merges 2 dataframes into a single one with the format sender -> receiver
Maintainer  : matt

To compute some statistics, it is necessary
to be able to map packets captured on the server to the ones mapped on the client.

For instance if clocks on both hosts are synchronized and we know the mapping, we can compute the One-Way-Delay (OWD). It is usually assumed to be half the roundtrip, also because there is almost no tooling to measure it.

Another example where it is useful is when dealing with retransmissions, you may want
to identify what transmission arrived first in order to classify between successful
and penalizing retransmissons.
A similar analysis applies to MPTCP streams as reinjections can happen cross-subflows.
If we can distinguish the first successful transmission from the redundant ones,
it becomes possible to compute the real contribution ("goodput") of a subflow to
the overall MPTCP transmission.
We can thus compare different retransmissions schemes, a crucial area of research 
in the MPTCP community.

You can easily generate retransmissions using the "redundant scheduler".

-}
{-# LANGUAGE TypeApplications             #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE PolyKinds             #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# OPTIONS_GHC -O0 #-}
module MptcpAnalyzer.Merge
where

import Prelude hiding (log)
import MptcpAnalyzer.Types
import Tshark.TH
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Types
-- for retypeColumn
import MptcpAnalyzer.Frames.Utils
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Map
-- (addTcpDestToFrame, StreamConnection)


import Frames as F
import Frames.CSV
import Frames.Joins
import Data.List (sortBy, sortOn, intersperse, intercalate)
import Data.Vinyl
import Data.Vinyl.TypeLevel
import Data.Vinyl.TypeLevel as V --(type (++), Snd)
import Data.Hashable
import GHC.TypeLits (KnownSymbol, Symbol)
import qualified Data.Vinyl as V
import Language.Haskell.TH (Name)
import Net.IP (IP)
import Net.Tcp
import Net.Mptcp
import Data.Word (Word8, Word16, Word32, Word64)
import Data.Maybe (catMaybes)
import Data.Foldable (toList)
import Control.Lens
import Frames.Melt          (RDeleteAll, ElemOf)
import Data.Either (fromRight)

import qualified Pipes as Pipes
import qualified Pipes.Prelude as Pipes
import qualified Data.Foldable as F
import Polysemy
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import qualified Polysemy.Embed as P
import qualified Control.Foldl                  as L

-- convert_to_sender_receiver
-- merge_tcp_dataframes_known_streams(
-- map_tcp_packets_via_hash
-- map_mptcp_connection_from_known_streams(
-- classify reinjections

-- PacketMerged should be TCP/MPTCP


-- TODO use inner join / outer join hash
-- mapMptcpConnectionsFromKnownStreams :: FrameFiltered Packet -> FrameFiltered Packet -> FrameFiltered PacketMerged
-- mapMptcpConnectionsFromKnownStreams =

type Score = Int


-- def map_mptcp_connection_from_known_streams(
--     main: MpTcpConnection,
--     other: MpTcpConnection
-- ) -> MpTcpMapping:
--     """
--     Attempts to map subflows only if score is high enough
--     """
--     def _map_subflows(main: MpTcpConnection, mapped: MpTcpConnection):
--         """
--         """
--         mapped_subflows = []
--         for sf in main.subflows():

--             # generates a list (subflow, score)
--             scores = list(map(lambda x: TcpMapping(x, sf.score(x)), mapped.subflows()))
--             scores.sort(key=lambda x: x.score, reverse=True)
--             log.log(mp.TRACE, "sorted scores when mapping %s:\n %r" % (sf, scores))
--             mapped_subflows.append((sf, scores[0]))
--         return mapped_subflows

--     mptcpscore = main.score(other)
--     mapped_subflows = None
--     if mptcpscore > float('-inf'):
--         # (other, score)
--         mapped_subflows = _map_subflows(main, other)

--     mapping = MpTcpMapping(mapped=other, score=mptcpscore, subflow_mappings=mapped_subflows)
--     log.log(mp.TRACE, "mptcp mapping %s", mapping)
--     return mapping



-- prefix
-- type PacketMerged =
toHashablePacket :: Record HostCols -> Record HashablePart
toHashablePacket = rcast

-- instance Hashable (Rec ElField a) where

-- -- TODO should generate a column and add it back to HostCols
-- -- type FieldRec = Rec ElField
-- addHash :: FrameFiltered Packet -> Frame (Record (PacketHash ': HashablePart))
-- addHash aframe =
--   fmap (addHash')  ( frame)
--   where
--     frame = fmap toHashablePacket (ffFrame aframe)
--     addHash' row = Col (hashWithSalt 0 row) :& row

-- generate a column and add it back to HostCols
addHash :: StreamConnection a b => FrameFiltered a Packet -> Frame (Record '[PacketHash] )
addHash aframe =
  -- addHashToFrame (ffFrame aframe)
  fmap (addHash')  (frame)
  where
    frame = fmap toHashablePacket (ffFrame aframe)
    addHash' row = Col (hash row) :& RNil

addHashToFrame :: Frame Packet -> Frame (Record '[PacketHash] )
addHashToFrame frame =
  fmap (addHash')  (frame')
  where
    frame' = fmap toHashablePacket frame
    addHash' row = Col (hash row) :& RNil


-- '[TcpDest] V.++
type MergedHostCols = PacketHash ': '[SenderDest] V.++ HostCols V.++ HostColsPrefixed
type MergedHostColsMptcp = PacketHash ': '[SenderDest] V.++ HostCols V.++ HostColsPrefixed

-- not a frame but hope it should be
-- type MergedPcap a = [Rec (Maybe :. ElField) a]
type MergedPcap = [Rec (Maybe :. ElField) MergedHostCols]

type MergedFrame = FrameRec MergedHostCols
-- type MergedFrameTcp = FrameRec (TcpDest ': MergedHostCols)
-- type MergedFrameMptcp = FrameRec (MptcpDest ': MergedHostCols)

-- liste de
mergedPcapToFrame :: MergedPcap -> (FrameRec MergedHostCols, MergedPcap)
mergedPcapToFrame mergedRes = let
  -- P.embed $ putStrLn $ "There are " ++ show (length justRecs) ++ " valid merged rows (out of " ++ show (length mergedRes) ++ " merged rows)"
  -- P.embed $ putStrLn $ (concat . showFields) (head justRecs)
    mbRecs = map recMaybe mergedRes
    justRecs = catMaybes mbRecs
  in
    (toFrame justRecs, [])


writeMergedPcap :: FilePath -> MergedPcap -> IO ()
writeMergedPcap outPath mergedPcap = do
  -- showReinjects frame =
    -- unlines (intercalate sep (columnHeaders (Proxy :: Proxy (Record rs))) : rows)
    writeFile outPath content
    where
      content = intercalate "," rows
      rows = Pipes.toList (F.mapM_ (Pipes.yield . show ) mergedPcap)


showMergedRes :: MergedPcap -> String
showMergedRes mergedPcap = do
  -- showReinjects frame =
    -- unlines (intercalate sep (columnHeaders (Proxy :: Proxy (Record rs))) : rows)
    -- writeFile outPath content
    content
    where
      content = intercalate "\n" rows
      rows = Pipes.toList (F.mapM_ (Pipes.yield . show ) mergedPcap)

--
-- | Drop a column from a record.  Just a specialization of rcast.
dropColumn :: forall x rs. (F.RDelete x rs F.⊆ rs) => F.Record rs -> F.Record (F.RDelete x rs)
dropColumn = F.rcast


-- | Merge of 2 frames
-- TODO add MptcpDest
mergeMptcpConnectionsFromKnownStreams ::
  (Members '[Log, P.Embed IO] r)
  => FrameFiltered MptcpConnection Packet
  -> FrameFiltered MptcpConnection Packet
  -> Sem r MergedFrame
  -- ^ merged frame
mergeMptcpConnectionsFromKnownStreams (FrameTcp con1 frame1) (FrameTcp con2 frame2) = do
  let mappedSubflows = mapSubflows con1 con2
  Log.info $ "Merging MPTCP frame1 " <> tshow (frameLength frame1) <> " and frame2 " <> tshow (frameLength frame2)
  Log.info $ "Mapped subflows:\n" <> showMptcpSubflowMapping mappedSubflows
  -- mergedFrames = map
  mergedFrames <- mapM  mergeSubflow mappedSubflows
  -- Log.info $ tshow (length mergedPackets) <> " merged lists"
  let res = mconcat mergedFrames
  Log.info $ tshow (frameLength res) <> " concatenated merged packets"
  return res
  where
    -- convertDest :: Record (MptcpDest ': TcpDest ': HostCols) -> Record (SenderDest ': HostCols)
    -- convertDest = withNames . stripNames
    convertDest :: Record '[MptcpDest] -> Record '[SenderDest]
    convertDest = withNames . stripNames

    -- frameWithDests = addMptcpDest frame1 con1 

    -- frameWithSenderDest :: FrameRec (MptcpDest ': TcpDest ': HostCols) -> FrameRec (SenderDest ': HostCols)
    -- frameWithSenderDest = fmap convertDest frameWithDests

    -- mergeSubflow :: (MptcpSubflow, [(MptcpSubflow, Int)]) -> MergedPcap
    mergeSubflow (sf1, scores) = do
      Log.debug $ "Merging pcap1 " <> tshow streamId1 <> " (" <> tshow (frameLength $ ffFrame aframe1)
          <> " packets) and " <> tshow streamId2 <> " (" <> tshow (frameLength $ ffFrame aframe2) <> " packets)"

      -- TODO add MptcpDest and recast to senderDest
      -- addMptcpDestToSubflowFrame
      mergedSf <- mergeTcpSubflowFromKnownStreams
            (FrameTcp (ffCon aframe1) (zipFrames aframe1Dest (ffFrame aframe1)))
            aframe2
      -- TODO print justRecs / 
      -- let
      --   mbRecs = map recMaybe mergedSf
      --   justRecs = catMaybes mbRecs
      -- -- Log.debug $ "Merging pcap1 stream" <> tshow streamId1 <> " (" <> tshow (frameLength frame1)
      --     -- <> " packets) and " <> tshow streamId2 <> " (" <> tshow (frameLength frame2) <> " packets)"
      -- Log.debug $ "There are " <> tshow (length justRecs) <> " valid rows (out of " 
      --   <> tshow (length mergedSf) <> " merged rows)"
      -- Log.debug $ (concat . showFields) (head justRecs)

      return mergedSf
      where
        streamId1 = conTcpStreamId $ sfConn sf1
        -- here we assume it's ordered but it might not be the case
        streamId2 = conTcpStreamId $ sfConn $ fst (head scores)

        aframe1 = fromRight undefined (buildFrameFromStreamId frame1 streamId1)
        aframe2 = fromRight undefined (buildFrameFromStreamId frame2 streamId2)

        aframe1Dest = fmap convertDest (addMptcpDestToFrame con1 aframe1)

-- mergeMptcpConnectionsFromKnownStreams' ::
--   FrameFiltered MptcpConnection Packet
--   -> FrameFiltered MptcpConnection Packet
--   -> MergedPcap
-- mergeMptcpConnectionsFromKnownStreams' (FrameTcp con1 frame1) (FrameTcp con2 frame2) = let
--   -- first we need to map subflow to oneanother
--   -- map mpconSubflows
--     mappedSubflows = mapSubflows con1 con2
--     mergedFrames = map mergeSubflow mappedSubflows

--     -- aframeSf1 = buildFrameFromStreamId frame1 (conTcpStreamId $ sfConn con1) 
--     -- aframeSf1 = buildFrameFromStreamId frame2 (conTcpStreamId $ sfConn con1) 
--     -- sf1 = buildTcpConnectionFromStreamId (

--     -- :: MptcpSubflow ->
--     mergeSubflow :: (MptcpSubflow, [(MptcpSubflow, Int)]) -> MergedPcap
--     mergeSubflow (sf1, scores) = mergeTcpConnectionsFromKnownStreams' aframe1 aframe2
--       where
--         aframe1 = fromRight undefined (buildFrameFromStreamId frame1 (conTcpStreamId $ sfConn sf1) )
--         aframe2 = fromRight undefined (buildFrameFromStreamId frame2 (conTcpStreamId $ sfConn $ fst (head scores ) ))
--                                     -- (FrameFiltered (sfConn sf) frame1)
--                                     -- (FrameFiltered (sfConn sf) frame2)
--   in
--     mconcat mergedFrames


validateMergedRes ::
  (Members '[Log, P.Embed IO] r)
  => MergedPcap
  -> Sem r Bool
validateMergedRes l = do
  Log.debug "validating mergedRes"
  -- rows = Pipes.toList (F.mapM_ (Pipes.yield . show ) mergedPcap)
  -- return $ L.nub (view packetId <$> l) /= length l
  return True

-- mergeTcpSubflow ::


mergeTcpSubflowFromKnownStreams :: 
  (Members '[Log, P.Embed IO] r)
  => FrameFiltered MptcpSubflow PacketWithSenderDest
  -> FrameFiltered MptcpSubflow Packet
  -> Sem r MergedFrame
mergeTcpSubflowFromKnownStreams (FrameTcp sfcon1 frame1) (FrameTcp sfcon2 frame2) =
  mergeTcpConnectionsFromKnownStreams (FrameTcp (sfConn sfcon1) frame1)
      (FrameTcp (sfConn sfcon2) frame2)

mergeTcpConnectionsFromKnownStreams ::
  (Members '[Log, P.Embed IO] r)
  => FrameFiltered TcpConnection PacketWithSenderDest
  -> FrameFiltered TcpConnection Packet
  -> Sem r MergedFrame
-- these are from host1 / host2
mergeTcpConnectionsFromKnownStreams aframe1 aframe2 = do
  Log.debug $ "Merging stream " <> showConnectionText (ffCon aframe1) <> " with stream "
  -- Ziggy Marley
  embed $ writeDSV defaultParserOptions out1 hframe1
  embed $ writeDSV defaultParserOptions out2 hframe2

  return $ (fst . mergedPcapToFrame) mergedRes
  where
    -- frame1withDest = addTcpDestToFrame (ffFrame aframe1) (ffCon aframe1)
    frame1withDest = (ffFrame aframe1)

    out1 = "merge-tcp-1-stream-" ++ show ((conTcpStreamId . ffCon) aframe1) ++ ".tsv"
    out2 = "merge-tcp-2-stream-" ++ show (conTcpStreamId $ ffCon aframe2) ++ ".tsv"

    -- we want an outerJoin , maybe with a status column like in panda
    -- outerJoin returns a list of [Rec (Maybe :. ElField) ors]
    mergedRes = leftJoin @'[PacketHash] (hframe1dest) processedFrame2


    -- (rcast @HostCols )
    -- hframe1 = zipFrames (addHash $ fmap (rcast @Packet) (ffFrame aframe1)) (ffFrame aframe1)
    hframe1 = zipFrames (addHashToFrame $ fmap (rcast @HostCols) (ffFrame aframe1)) (ffFrame aframe1)
    hframe1dest = hframe1
    -- hframe1dest = addTcpDestinationsToAFrame hframe1
    hframe2 :: Frame (Record ('[PacketHash] ++ HostColsPrefixed))
    hframe2 = zipFrames (addHash aframe2) host2_frame

    host2_frame = convertToHost2Cols (ffFrame aframe2)
    processedFrame2 = hframe2


-- | Merge of 2 frames
-- inspired by merge_tcp_dataframes_known_streams
-- mergeTcpConnectionsFromKnownStreams' ::
--   FrameFiltered TcpConnection Packet
--   -> FrameFiltered TcpConnection Packet
--   -> MergedPcap
-- -- these are from host1 / host2
-- mergeTcpConnectionsFromKnownStreams' aframe1 aframe2 =
--   mergedFrame
--   where
--     -- (Record HostColsPrefixed)
--     -- we want an outerJoin , maybe with a status column like in panda
--     -- outerJoin returns a list of [Rec (Maybe :. ElField) ors]
--     mergedFrame = outerJoin @'[PacketHash] (hframe1dest) processedFrame2

--     frame1withDest = addTcpDestToFrame (ffFrame aframe1) (ffCon aframe1)

--     hframe1 = zipFrames (addHash aframe1) frame1withDest
--     hframe1dest = hframe1
--     -- hframe1dest = addTcpDestinationsToAFrame hframe1
--     hframe2 :: Frame (Record ('[PacketHash] ++ HostColsPrefixed))
--     hframe2 = zipFrames (addHash aframe2) host2_frame

--     host2_frame = convertToHost2Cols (ffFrame aframe2)
--     processedFrame2 = hframe2

-- | Result of the merge of 2 pcaps
-- genExplicitRecord "" "HostCols" mergedFields

-- gen https://hackage.haskell.org/package/vinyl-0.13.1/docs/Data-Vinyl-Derived.html
convertToHost2Cols :: FrameRec HostCols -> FrameRec HostColsPrefixed
convertToHost2Cols frame = fmap convertCols' frame
  where
    convertCols' :: Record HostCols -> Record HostColsPrefixed
    convertCols' = withNames . stripNames
    -- if you need a review on a specific patch, let us know
    -- stripNames r
    -- convertCols' r = F.rcast @HostColsPrefixed (retypeColumns @'[ '("fakePacketId", "fake_fakePacketId", Word64), '("fakeInterfaceName", "fake_fakeInterfaceName", Text) ] r)

-- convertCols :: Record a -> Record b
-- convertCols = withNames . stripNames 

-- TODO and then we should compute a owd
-- , RcvAbsTime
-- type SenderReceiverCols =  '[SndPacketId, RcvPacketId, SndAbsTime, RcvAbsTime, TcpDest]
-- TODO il nous faut le hash + la dest
-- | SenderHost
type TcpSenderReceiverCols =  SenderHost ': TcpDest ': SenderCols V.++ ReceiverCols
type SenderReceiverCols =  SenderHost ': SenderDest ': SenderCols V.++ ReceiverCols
type MptcpSenderReceiverCols =  SenderHost ': MptcpDest ': SenderCols V.++ ReceiverCols



-- FrameMergedOriented
-- inspirted by convert_to_sender_receiver
-- TODO this should be for a TCP frame
--
-- In the mergedpcap we have mapped packets from 2 hosts. We then have to decide
-- between the 2 hosts which one acted as a client and which one as the server.
--
-- @param j
--  Convert dataframe from  X_HOST1 ': X_HOST2 to X_SENDER ': X_RECEIVER
--  Each mapping PACKET_HOST_1 <-> PACKET_HOST_2 is associated with its destination Server/Client
--  We thus need to find out which host acted as a Client or Server;
--  then we can select packets whose destination is the Server
--  and for those packets set the Sender to HOST1 or HOST2
--
-- 1/ we compare the abstime of the first packet (TODO we could select the role instead ?!)
convertToSenderReceiver ::
  MergedFrame
  -> FrameRec SenderReceiverCols
convertToSenderReceiver oframe = do
  -- compare first packet time
  if delta > 0 then
    -- host1 is the client
    -- then rename into sndTime, rcvTime
    -- TODO
    -- convertHost1AsClient
    setHost1AsSenderForDest RoleServer <> setHost2AsSenderForDest RoleClient
  else
    -- TODO zarb because it's the same as before
    setHost1AsSenderForDest RoleServer <> setHost2AsSenderForDest RoleClient

  where
    -- tframe :: [Maybe (Record MergedHostCols)]
    -- tframe = fmap recMaybe oframe

    -- jframe :: FrameRec MergedHostCols
    -- jframe = toFrame $ catMaybes $ toList tframe
    jframe = oframe

    firstRow = frameRow jframe 0

    -- instead of taking firstRow we should compare the minima in case there are retransmissions
    delta :: Double
    delta =  (firstRow ^. testAbsTime) - (firstRow ^. absTime)

    selectDest :: ConnectionRole -> FrameRec MergedHostCols
    selectDest dest = filterFrame (\x -> x ^. senderDest == dest) jframe

    -- em fait le retype va ajouter la colonne a la fin seulement
    -- zipFrames
    setHost1AsSenderForDest, setHost2AsSenderForDest  :: ConnectionRole -> FrameRec SenderReceiverCols
    setHost1AsSenderForDest dest = fmap (\x -> Col False :& convertToSender x ) (selectDest dest)

    -- (if h1role == RoleClient then RoleServer else RoleClient))
    setHost2AsSenderForDest  dest = fmap (\x -> Col True :& convertToReceiver x ) (selectDest dest)

    -- convertToSender, convertToReceiver :: Record MergedHostCols -> Record SenderReceiverCols
    convertToSender r = let
        -- TODO add tcpDest
        senderCols :: Record SenderCols
        senderCols = (withNames . stripNames . F.rcast @HostCols) r
        receiverCols :: Record ReceiverCols
        receiverCols = (withNames . stripNames . F.rcast @HostColsPrefixed) r
      in
        rget @SenderDest r :& (rappend senderCols receiverCols)

    convertToReceiver r = let
        senderCols :: Record SenderCols
        senderCols = (withNames . stripNames . F.rcast @HostColsPrefixed) r
        receiverCols :: Record ReceiverCols
        receiverCols = (withNames . stripNames . F.rcast @HostCols) r
      in
        (rget @SenderDest r) :& (rappend senderCols receiverCols)
        -- convert ("first host") to sender/receiver
        -- TODO this could be improved


-- | Add a One-Way-Delay column to the results
-- addOWD :: Frame (Record RecSenderReceiver) -> Frame (Record '[OWD] ++ RecSenderReceiver)
-- addOWD = fmap addOWD'
--   where
--     addOWD' = (rcvAbsTime x - sndAbsTime x)
