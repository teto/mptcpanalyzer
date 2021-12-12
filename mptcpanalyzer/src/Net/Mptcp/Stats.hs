{-|
Module      : Net.Mptcp.Stats
Description : Compute basic MPTCP statistics
Maintainer  : matt
License     : GPL-3
-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE StandaloneDeriving #-}
module Net.Mptcp.Stats (
  TcpSubflowUnidirectionalStats(..)
  , MptcpUnidirectionalStats(..)
  , getMptcpStats
  , getMptcpGoodput
  , getMptcpStatsDuration
  , getSubflowStats
  , showMptcpUnidirectionalStats
)
where

import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Units

import qualified Data.Map as Map
import Net.Mptcp.Connection
import Net.Tcp
import Net.Tcp.Stats

import Data.Either (fromRight)
import Data.Text (Text)
import qualified Data.Text as T

import Control.Lens
import Control.Lens hiding (argument)
import qualified Data.Foldable as F
import Data.List (sort, sortBy, sortOn)
import Data.Map (Map, fromList, mapKeys)
import qualified Data.Map as Map
import Data.Maybe (catMaybes, fromJust)
import Data.Set (toList)
import Data.Vinyl
import Data.Word (Word32, Word64)
import qualified Frames as F
import qualified Frames.InCore as F
import MptcpAnalyzer.Types
-- import MptcpAnalyzer.Pcap (addTcpDestinationsToAFrame)

-- | Useful to show DSN
data TcpSubflowUnidirectionalStats = TcpSubflowUnidirectionalStats {
  -- tssStats :: TcpUnidirectionalStats
  tssStats    :: TcpUnidirectionalStats
  , tssMinDsn :: Word64
  , tssMaxDsn :: Word64
  } deriving Show
-- newtype TcpSubflowUnidirectionalStats = TcpSubflowUnidirectionalStats

instance Semigroup TcpSubflowUnidirectionalStats where
   -- (<>) :: a -> a -> a
   -- TODO this does nothing
   (<>) a b = a

instance Monoid TcpSubflowUnidirectionalStats where
  mempty = TcpSubflowUnidirectionalStats {
      tssStats = mempty 
    , tssMinDsn = 0
    , tssMaxDsn = 0
    }


-- | Holds MPTCP application level statistics for one direction
data MptcpUnidirectionalStats = MptcpUnidirectionalStats {
  musDirection          :: ConnectionRole
  , musApplicativeBytes :: Word64
  , musMaxDsn           :: Word64
  , musMinDsn           :: Word64
  , musSubflowStats     :: Map MptcpSubflow TcpSubflowUnidirectionalStats
  } deriving Show

instance Monoid MptcpUnidirectionalStats where
  mempty = MptcpUnidirectionalStats RoleServer 0 0 0 mempty

instance Semigroup MptcpUnidirectionalStats where
  -- TODO fix
  (<>) s1 s2 = s1


    -- ''' application data = goodput = useful bytes '''
    -- ''' max(dsn)- min(dsn) - 1'''
    -- mptcp_application_bytes: Byte

    -- '''Total duration of the mptcp connection'''
    -- mptcp_duration: datetime.timedelta
    -- subflow_stats: List[TcpUnidirectionalStats]

    -- @property
    -- def mptcp_throughput_bytes(self) -> Byte:
    --     ''' sum of total bytes transferred '''
    --     return Byte(sum(map(lambda x: x.throughput_bytes, self.subflow_stats)))

-- |Goodput is defined as the amount of effective data exchanged over time
-- I.e., (maxDsn - minDsn) / (Mptcp communication Duration)
getMptcpGoodput :: MptcpUnidirectionalStats -> Throughput
getMptcpGoodput s = Throughput (Bytes $ musApplicativeBytes s) ((getMptcpStatsDuration s) ^. _1)

-- fromIntegral

-- | return max - min across subflows
getMptcpStatsDuration :: MptcpUnidirectionalStats -> (Duration, Timestamp, Timestamp)
getMptcpStatsDuration s = (diffTime end start, start, end)
  where
    start = Timestamp $ head $ sort starts
    end = Timestamp $ last $ sort ends
    -- min of
    -- TODO get min
    starts = map (tusStartTime . tssStats) (Map.elems $ musSubflowStats s)
    -- take the maximum
    ends = map (tusEndTime . tssStats) (Map.elems $ musSubflowStats s)


-- | TcpSubflowUnidirectionalStats
getSubflowStats ::
  (TcpSeq F.∈ rs, F.RecVec rs, RelTime F.∈ rs, TcpLen F.∈ rs
  , PacketId F.∈ rs
    , IpSource ∈ rs, IpDest ∈ rs, TcpSrcPort ∈ rs, TcpDestPort ∈ rs, TcpStream ∈ rs
  -- , TcpDest F.∈ rs
  )
  => FrameFiltered MptcpSubflow (F.Record rs) -> ConnectionRole -> TcpSubflowUnidirectionalStats
getSubflowStats aframe role = TcpSubflowUnidirectionalStats {
      tssStats = getTcpStats (addTcpDestinationsToAFrame aframe') role
      , tssMinDsn = 0
      , tssMaxDsn = 0
    }
    where
      aframe' = FrameTcp (sfConn $ ffCon aframe) (ffFrame aframe)

-- mptcp_compute_throughput est bourrin il calcule tout d'un coup, je veux avoir une version qui marche iterativement
getMptcpStats ::
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
  -> ConnectionRole
  -> MptcpUnidirectionalStats
getMptcpStats (FrameTcp mptcpConn frame) dest =
  MptcpUnidirectionalStats {
    musDirection = dest
    , musApplicativeBytes = getSeqRange maxDsn minDsn
    , musMaxDsn = maxDsn
    , musMinDsn = minDsn
    -- we need the stream id / FrameFiltered MptcpSubflow (Record rs)
    , musSubflowStats = Map.fromList $ map (\sf -> (sf, getStats dest sf))  (toList $ mpconSubflows mptcpConn)
  }
  where
    -- buildTcpConnectionFromStreamId :: SomeFrame -> StreamId Tcp -> Either String (FrameFiltered TcpConnection Packet)
    -- traverse a set
    getStats role sf = let
        sfFrame = fromRight (error "could not build sfFrame") (buildSubflowFromTcpStreamId frame (conTcpStreamId $ sfConn sf))
        -- sfFrame' = addTcpDestinationsToAFrame sfFrame
      in
        getSubflowStats sfFrame role

    -- frame = addTcpDestToFrame $ ffFrame aframe
    -- these return Maybes
    -- minSeq = minimum (F.toList $ view tcpSeq <$> frame)
    -- maxSeq = maximum $ F.toList $ view tcpSeq <$> frame

    maxTime = maximum $ F.toList $ view relTime <$> frame
    minTime = minimum $ F.toList $ view relTime <$> frame

    -- dsn_range, dsn_max, dsn_min = transmitted_seq_range(df, "dsn")
    -- mbRecs = map recMaybe mergedRes
    -- justRecs = catMaybes mbRecs
  -- in
    -- (toFrame justRecs, [])

    dsns = catMaybes $ F.toList $ view mptcpDsn <$> frame

    -- mergedPcapToFrame
    maxDsn, minDsn :: Word64
    maxDsn = maximum dsns

    minDsn = minimum dsns

showMptcpUnidirectionalStats :: MptcpUnidirectionalStats -> Text
showMptcpUnidirectionalStats stats = T.unlines [
  "MptcpUnidirectionalStats todo"
  ]
