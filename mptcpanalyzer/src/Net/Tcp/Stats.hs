{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE StandaloneDeriving #-}
{-
Module:  Net.Tcp.Stats
Description : Uni/bidirectional statistics for subflows
Maintainer  : matt
Portability : Linux
-}

module Net.Tcp.Stats (
  TcpUnidirectionalStats (..)
  , getTcpGoodput
  , getTcpThroughput
  , getTcpSeqRange
  , getTcpStats
  , getSeqRange
  , showTcpUnidirectionalStats
)
where

import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Types
import MptcpAnalyzer.Utils.Text
import Net.Tcp.Connection

import qualified Control.Foldl as L
import Control.Lens hiding (argument)
import qualified Data.Map as Map
import Data.Maybe (fromJust)
import Data.Word (Word32, Word64)
-- import Data.ByteUnits

import qualified Data.Foldable as F
import Data.Ord (comparing)
import qualified Data.Text as T
import Frames
import qualified Frames as F
import qualified Frames.InCore as F

type Byte = Int

-- tus = tcp Unidrectional Stats
data TcpUnidirectionalStats = TcpUnidirectionalStats {
    -- sum of tcplen / should be the same for tcp/mptcp
    -- Include redundant packets contrary to '''
    -- tusThroughput :: Byte

    tusStartPacketId :: Word64
    , tusEndPacketId :: Word64
    , tusNrPackets :: Int
    -- duration
    -- , tusDuration :: Double
    , tusStartTime :: Double
    , tusEndTime :: Double

    -- For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    -- , tusMinSeq :: Word32
    -- , tusMaxSeq :: Word32

    -- transferred bytes
    -- , tusCumulativeBytes :: Map Word64 Word16
    , tusMinSeq :: Word32
    , tusSndUna :: Word32
    , tusSndNext :: Word32
    -- , tusReinjectedBytes :: Map Word64 Word16
    , tusReinjectedBytes :: Word32 -- ^Amount of reinjected bytes
    -- , tusUniqueBytes :: Word64

    -- , tusMinAck :: Word32
    -- , tusMaxAck :: Word32

    -- application data = goodput = useful bytes '''
    -- TODO move to its own ? / Maybe
    -- , mptcp_application_bytes :: Byte
    -- , tusThroughputContribution :: Double
    -- , tusGoodputContribution :: Double

    -- TODO this should be updated
    -- For now = max(tcpseq) - minx(tcpseq). Should add the size of packets'''
    -- , tusGoodput :: Byte
    }  deriving Show
    -- deriving Semigroup via WrappedMonoid TcpUnidirectionalStats

-- deriving instance Semigroup TcpUnidirectionalStats
-- deriving instance Monoid TcpUnidirectionalStats

instance Semigroup TcpUnidirectionalStats where
   -- (<>) :: a -> a -> a
   -- TODO this does nothing
   (<>) a b = TcpUnidirectionalStats {
      -- tusThroughput = 0
      tusStartPacketId = min (tusStartPacketId a) (tusStartPacketId b)
      , tusEndPacketId = max (tusEndPacketId a) (tusEndPacketId b)
      , tusNrPackets = tusNrPackets a + tusNrPackets b
      , tusStartTime = min (tusStartTime a) (tusStartTime b)
      , tusEndTime = max (tusEndTime a) (tusEndTime b)
      -- TODO fill it
      , tusMinSeq = 0

      -- TODO should be max of seen acks
      , tusSndUna = 0
      , tusSndNext = 0
      , tusReinjectedBytes = 0
      -- , tusSnd = 0
      -- , tusNumberOfPackets = mempty
    }

instance Monoid TcpUnidirectionalStats where
  mempty = TcpUnidirectionalStats {
      -- tusThroughput = 0
      tusStartPacketId = 0 -- (frameRow frame 0) ^. packetId
      , tusEndPacketId = 0 -- (frameRow frame (frameLength frame - 1)) ^. packetId
      , tusNrPackets = 0
      , tusStartTime = 0
      , tusEndTime = 0
      , tusMinSeq = 0        -- TODO fill it

      -- TODO should be max of seen acks
      , tusSndUna = 0
      , tusSndNext = 0
      , tusReinjectedBytes = 0
      -- , tusSnd = 0
      -- , tusNumberOfPackets = mempty
    }

-- | TODO check boundaries etc
getSeqRange :: Num a => a -> a
  -> a
  -- -> (a, a, a)
-- getSeqRange maxSeq minSeq = (maxSeq - minSeq + 1, maxSeq, minSeq)
getSeqRange maxSeq minSeq = maxSeq - minSeq + 1



-- TODO add a Functor to FilteredFrame
genTcpStats :: Frame Packet -> TcpUnidirectionalStats
genTcpStats aframe = TcpUnidirectionalStats {

    -- TODO we should run a minmax instead
    tusStartPacketId = minPktId
    , tusEndPacketId = maxPktId
    , tusNrPackets = frameLength aframe
    --     maxTime = maximum $ F.toList $ view relTime <$> frame
    -- minTime = minimum $ F.toList $ view relTime <$> frame

    -- We could just take first and last
    , tusStartTime = minTime
    , tusEndTime = maxTime

    , tusMinSeq = 0
    , tusSndUna = 0
    , tusSndNext = 0
    , tusReinjectedBytes = 0
  }
  where
    -- we could use the Statistics vector if we could use the
    (minPktId, maxPktId) = case L.fold ((,) <$> L.minimum <*> L.maximum) $ F.toList $ view packetId <$> aframe of
        (Just pmin, Just pmax) -> (pmin, pmax)
        _otherwise -> error "Could not find either min or max"

    (minTime, maxTime) = case L.fold ((,) <$> L.minimum <*> L.maximum) $ F.toList $ view relTime <$> aframe of
        (Just pmin, Just pmax) -> (pmin, pmax)
        _otherwise -> error "Could not find either min or max"

    (minSeq, maxSeq) = case L.fold ((,) <$> L.minimum <*> L.maximum) $ F.toList $ view tcpSeq <$> aframe of
        (Just pmin, Just pmax) -> (pmin, pmax)
        _otherwise -> error "Could not find either min or max"

-- ⊆
getTcpStats :: (
  TcpSeq F.∈ rs, TcpDest F.∈ rs, F.RecVec rs, TcpLen F.∈ rs, RelTime F.∈ rs
  , PacketId F.∈ rs
  )
  => FrameFiltered TcpConnection (F.Record rs)
  -> ConnectionRole
  -> TcpUnidirectionalStats
getTcpStats aframe dest =
  if frameLength frame == 0 then
    mempty
  else
    TcpUnidirectionalStats {
      -- tusThroughput = 0
      tusStartPacketId = 0 -- (frameRow frame 0) ^. packetId
      , tusEndPacketId = 0 -- (frameRow frame (frameLength frame - 1)) ^. packetId
      , tusNrPackets = frameLength frame
      , tusStartTime = minTime
      , tusEndTime = maxTime
      -- TODO fill it
      , tusMinSeq = minSeq

      -- TODO should be max of seen acks
      , tusSndUna = maxSeqRow ^. tcpSeq + fromIntegral ( maxSeqRow ^. tcpLen) :: Word32
      , tusSndNext = maxSeqRow ^. tcpSeq + fromIntegral ( maxSeqRow ^. tcpLen ) :: Word32
      , tusReinjectedBytes = 0
      -- , tusSnd = 0
      -- , tusNumberOfPackets = mempty
    }
  where
    frame = F.filterFrame (\x -> x ^. tcpDest == dest) (ffFrame aframe)

    -- these return Maybes
    -- I need to find its id and add tcpSize afterwards
    -- TODO use     minimumBy
    minSeq = case F.toList $ view tcpSeq <$> frame of
      [] -> 0
      l -> minimum l
    -- maxSeq = maximum $ F.toList $ view tcpSeq <$> frame

    -- $ F.toList $ view tcpSeq <$> frame
    maxSeqRow = F.maximumBy (comparing (^. tcpSeq)) frame

    -- compareRows x y = if (x ^. tcpSeq) (y ^. tcpSeq)

    maxTime = maximum $ F.toList $ view relTime <$> frame
    minTime = minimum $ F.toList $ view relTime <$> frame


-- byteValue
getTcpSeqRange :: TcpUnidirectionalStats -> Double
getTcpSeqRange s =
  fromIntegral (tusSndUna s - tusMinSeq s - 1)

-- | Computes throughput
getTcpThroughput :: TcpUnidirectionalStats -> Double
getTcpThroughput s =
  fromIntegral (tusSndUna s - tusMinSeq s - 1) / (tusEndTime s - tusStartTime s)

-- | Computes goodput
getTcpGoodput :: TcpUnidirectionalStats -> Double
getTcpGoodput s =
  fromIntegral (tusSndUna s - tusMinSeq s + 1 - tusReinjectedBytes s) / (tusEndTime s - tusStartTime s)

showTcpUnidirectionalStats :: TcpUnidirectionalStats -> Text
showTcpUnidirectionalStats stats =
  T.unlines [
    "Reinjected bytes: " <> tshow (tusReinjectedBytes stats)
    , "Current goodput: " <> tshow (getTcpGoodput stats)
  ]

    -- duration = maxTime - minTime



-- No instance for (Ord (Frames.Frame.Frame GHC.Word.Word32))
-- instance Ord a => Ord (Frame a)
-- def transmitted_seq_range(df, seq_name):
--     '''
--     test
--     '''
--     log.debug("Computing byte range for sequence field %s", seq_name)

--     sorted_seq = df.dropna(subset=[seq_name]).sort_values(by=seq_name)
--     log.log(mp.TRACE, "sorted_seq %s", sorted_seq)

--     seq_min = sorted_seq.loc[sorted_seq.first_valid_index(), seq_name]
--     last_valid_index = sorted_seq.last_valid_index()
--     seq_max = sorted_seq.loc[last_valid_index, seq_name] \
--         + sorted_seq.loc[last_valid_index, "tcplen"]

--     # -1 because of SYN
--     # seq_range = seq_max - seq_min - 1
--     seq_range = seq_max - seq_min - 1

--     msg = "seq_range ({}) = {} (seq_max) - {} (seq_min) - 1"
--     log.log(mp.TRACE, msg.format(seq_range, seq_max, seq_min))

--     return seq_range, seq_max, seq_min


  -- where
  --   packetStreams = filterStreamPackets frame streamId (Just role)
    -- log.debug("Getting TCP stats for stream %d", tcpstreamid)
    -- assert destination in ConnectionRoles, "destination is %r" % type(destination)

    -- df = rawdf[rawdf.tcpstream == tcpstreamid]
    -- if df.empty:
    --     raise MpTcpException("No packet with tcp.stream == %d" % tcpstreamid)

    -- df2 = df

    -- log.debug("df2 size = %d" % len(df2))
    -- log.debug("Looking at role %s" % destination)
    -- # assume it's already filtered ?
    -- sdf = df2[df2.tcpdest == destination]
    -- bytes_transferred = Byte(sdf["tcplen"].sum())
    -- assert bytes_transferred >= 0

    -- # -1 to account for SYN
    -- tcp_byte_range, seq_max, seq_min = transmitted_seq_range(sdf, "tcpseq")

    -- # print(sdf["abstime"].head())
    -- # print(dir(sdf["abstime"].dt))
    -- # print(sdf["abstime"].dt.end_time)
    -- times = sdf["abstime"]
    -- tcp_duration = times.iloc[-1] - times.iloc[0]
    -- # duration = sdf["abstime"].dt.end_time - sdf["abstime"].dt.start_time

    -- assert tcp_byte_range is not None

    -- return TcpUnidirectionalStats(
    --     tcpstreamid,
    --     tcp_duration=tcp_duration,
    --     throughput_bytes=bytes_transferred,
    --     # FIX convert to int because Byte does not support np.int64
    --     tcp_byte_range=Byte(tcp_byte_range)
    -- )
