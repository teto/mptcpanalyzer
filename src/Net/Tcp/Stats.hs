{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE DerivingVia #-}
module Net.Tcp.Stats
where

import MptcpAnalyzer.ArtificialFields
-- import MptcpAnalyzer.Types
-- import MptcpAnalyzer.Pcap
-- import MptcpAnalyzer.Frame
-- import MptcpAnalyzer.Stream
import Net.Tcp.Connection
import qualified Data.Map as Map


-- import qualified Control.Foldl as L
import Control.Lens hiding (argument)
import Data.Word (Word32, Word64)
import Data.Maybe (fromJust)
-- import Data.ByteUnits

import qualified Frames as F
import qualified Data.Foldable as F

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
    } 
    -- deriving Semigroup via WrappedMonoid TcpUnidirectionalStats

-- deriving instance Semigroup TcpUnidirectionalStats
-- deriving instance Monoid TcpUnidirectionalStats

instance Semigroup TcpUnidirectionalStats where
   -- (<>) :: a -> a -> a
   -- TODO this does nothing
   (<>) a b = TcpUnidirectionalStats {
      -- tusThroughput = 0
      tusStartPacketId = 0 -- (frameRow frame 0) ^. packetId
      , tusEndPacketId = 0 -- (frameRow frame (frameLength frame - 1)) ^. packetId
      , tusNrPackets = 0
      , tusStartTime = 0
      , tusEndTime = 0
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
      -- TODO fill it
      , tusMinSeq = 0

      -- TODO should be max of seen acks
      , tusSndUna = 0
      , tusSndNext = 0
      , tusReinjectedBytes = 0
      -- , tusSnd = 0
      -- , tusNumberOfPackets = mempty
    }


-- byteValue
getTcpSeqRange :: TcpUnidirectionalStats -> Double
getTcpSeqRange s =
  fromIntegral (tusSndUna s - tusMinSeq s - 1)

-- | Computes throughput
getThroughput :: TcpUnidirectionalStats -> Double
getThroughput s =
  fromIntegral (tusSndUna s - tusMinSeq s - 1) / (tusEndTime s - tusStartTime s)

-- | Computes goodput
getGoodput :: TcpUnidirectionalStats -> Double
getGoodput s =
  fromIntegral (tusSndUna s - tusMinSeq s + 1 - tusReinjectedBytes s) / (tusEndTime s - tusStartTime s)


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
