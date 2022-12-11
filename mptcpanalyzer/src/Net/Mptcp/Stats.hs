{-|
Module      : Net.Mptcp.Stats
Description : Compute basic MPTCP statistics
Maintainer  : matt
License     : GPL-3
-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
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
import Data.List (sort, sortBy, sortOn)
import Data.Map (Map, fromList, mapKeys)
import qualified Data.Map as Map
import Data.Maybe (catMaybes, fromJust)
import Data.Set (toList)
import Data.Vinyl
import Data.Word (Word32, Word64)
import qualified Data.Foldable as F
import qualified Frames as F
import qualified Frames.InCore as F
import MptcpAnalyzer.Types
import MptcpAnalyzer.Utils.Text
import Control.Exception (assert)
import Debug.Trace
-- import MptcpAnalyzer.Pcap (addTcpDestinationsToAFrame)

-- | Data Sequence Numbers (DSN) min and max in one direction
data TcpSubflowUnidirectionalStats = TcpSubflowUnidirectionalStats {
  -- tssStats :: TcpUnidirectionalStats
    tssStats  :: TcpUnidirectionalStats
  , tssMinDsn :: Word64
  , tssMaxDsn :: Word64
  } deriving Show
-- newtype TcpSubflowUnidirectionalStats = TcpSubflowUnidirectionalStats

instance Semigroup TcpSubflowUnidirectionalStats where
   -- (<>) :: a -> a -> a
   -- TODO this does nothing
   (<>) a b = TcpSubflowUnidirectionalStats {
            tssStats = tssStats a <> tssStats b
          , tssMinDsn = min (tssMinDsn a) (tssMinDsn b)
          , tssMaxDsn = max (tssMaxDsn a) (tssMaxDsn b)
          }

instance Monoid TcpSubflowUnidirectionalStats where
  mempty = TcpSubflowUnidirectionalStats {
      tssStats = mempty
    , tssMinDsn = 0
    , tssMaxDsn = 0
    }


-- | Holds MPTCP application level statistics for one direction
data MptcpUnidirectionalStats = MptcpUnidirectionalStats {
    musApplicativeBytes :: Bytes
  -- TODO these should be maybes ?
  , musMaxDsn           :: Word64
  , musMinDsn           :: Word64
  , musTime             :: Double
  , musSubflowStats     :: Map MptcpSubflow TcpSubflowUnidirectionalStats
  } deriving Show

instance Monoid MptcpUnidirectionalStats where
  mempty = MptcpUnidirectionalStats 0 0 0 0 mempty

instance Semigroup MptcpUnidirectionalStats where
  -- TODO fix
  (<>) s1 s2 =
      s1 {
            musMaxDsn = maxDsn
          , musMinDsn = minDsn
          , musApplicativeBytes = Bytes (maxDsn - minDsn)
        }
      where
        maxDsn = max (musMaxDsn s1) (musMaxDsn s2)
        minDsn = min (musMinDsn s1) (musMinDsn s2)


-- |Goodput is defined as the amount of effective data exchanged over time
-- I.e., (maxDsn - minDsn) / (Mptcp communication Duration)
getMptcpGoodput :: MptcpUnidirectionalStats -> Throughput
getMptcpGoodput s = Throughput (musApplicativeBytes s) ((getMptcpStatsDuration s) ^. _1)

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
  )
  => FrameFiltered MptcpSubflow (F.Record rs) -> ConnectionRole -> TcpSubflowUnidirectionalStats
getSubflowStats aframe role = TcpSubflowUnidirectionalStats {
      tssStats = getTcpStatsFromAFrame (addTcpDestinationsToAFrame aframe') role
      , tssMinDsn = 0
      , tssMaxDsn = 0
    }
    where
      aframe' = FrameTcp (connection $ ffCon aframe) (ffFrame aframe)


-- | Generates Stats for one direction only
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
      -- musDirection = trace ("setting dest to " ++ show dest ) dest
      musApplicativeBytes = Bytes $ getSeqRange maxDsn minDsn
    , musMaxDsn = maxDsn
    , musMinDsn = minDsn
    -- assume packet order has not been messed with
    , musTime = F.frameRow frame (F.frameLength frame - 1) ^. relTime
    -- we need the stream id / FrameFiltered MptcpSubflow (Record rs)
    , musSubflowStats = Map.fromList $ map (\sf -> (sf, getStats dest sf))  (toList $ subflows mptcpConn)
  }
  where
    -- buildTcpConnectionFromStreamId :: SomeFrame -> StreamId Tcp -> Either String (FrameFiltered TcpConnection Packet)
    -- traverse a set
    getStats role sf = let
        sfFrame = fromRight (error "could not build sfFrame") (buildSubflowFromTcpStreamId frame (streamId $ connection sf))
        -- sfFrame' = addTcpDestinationsToAFrame sfFrame
      in
        getSubflowStats sfFrame role

    maxTime = maximum $ F.toList $ view relTime <$> frame
    minTime = minimum $ F.toList $ view relTime <$> frame

    dsns = catMaybes $ F.toList $ view mptcpDsn <$> frame

    -- mergedPcapToFrame
    maxDsn, minDsn :: Word64
    maxDsn = maximum dsns
    minDsn = minimum dsns


showMptcpUnidirectionalStats :: MptcpUnidirectionalStats -> Text
showMptcpUnidirectionalStats stats = T.unlines [
  -- <> " towards " <> tshow (musDirection stats)
  "Min/max dsn: " <> tshow (musMinDsn stats) <> "/" <> tshow (musMaxDsn stats) 
  ]
