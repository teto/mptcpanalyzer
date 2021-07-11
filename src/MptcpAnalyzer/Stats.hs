module MptcpAnalyzer.Stats
where

import Net.Tcp
import Net.Mptcp
import MptcpAnalyzer.Frame
import Tshark.Fields
import MptcpAnalyzer.Types
import MptcpAnalyzer.ArtificialFields


import Frames
import qualified Frames as F
import qualified Frames.InCore as F
import qualified Data.Foldable as F
import Control.Lens hiding (argument)
import Data.Either (fromRight)
import MptcpAnalyzer.Pcap
import Data.Set (toList)
import Data.Maybe (catMaybes)
import Data.Word (Word32, Word64)
import Data.Ord (comparing)
import qualified Data.Map as Map

-- TODO should be able to update an initial one
-- type Packet = Record HostCols

-- ⊆
getTcpStats :: (
  TcpSeq F.∈ rs, TcpDest F.∈ rs, F.RecVec rs, TcpLen F.∈ rs, RelTime F.∈ rs
  , PacketId F.∈ rs
  )
  => FrameFiltered TcpConnection (F.Record rs)
  -> ConnectionRole -> TcpUnidirectionalStats
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
    }
    where
      aframe' = FrameTcp (sfConn $ ffCon aframe) (ffFrame aframe)


-- | TODO check boundaries etc
getSeqRange :: Num a => a -> a
  -> a
  -- -> (a, a, a)
-- getSeqRange maxSeq minSeq = (maxSeq - minSeq + 1, maxSeq, minSeq)
getSeqRange maxSeq minSeq = maxSeq - minSeq + 1

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


