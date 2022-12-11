{-|
Module      : MptcpAnalyzer.Maps
Description : Maps Packets and Tcp streams between two frames
Maintainer  : matt


Helper functions to map (mp)tcp.stream from one pcap to the one in another pcap.

For MPTCP, the association of mptcp.stream is done by identifying the same sendkey
in both pcaps.
For TCP, there is a similarity score computed on (IP, port) numbers. This could be
improved for sure (by comparing number of packets and other fields).

See "MptcpAnalyzer.Merge"
-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-deferred-out-of-scope-variables #-}
module MptcpAnalyzer.Map (
  mapMptcpConnection
  , mapTcpConnection
  , mapSubflows
  , showMptcpSubflowMapping
)
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Types
import MptcpAnalyzer.Utils.Text
import Net.Mptcp
import Net.Tcp

import Data.Either (lefts, rights)
import Data.Function (on)
import Data.List (sortBy, sortOn)
import Data.Ord
import qualified Data.Set as Set
import Data.Text (Text, intercalate, unlines)
import qualified Data.Text as T
import Frames
import Options.Applicative
import Polysemy (Embed, Member, Members, Sem)
import qualified Polysemy as P
import Polysemy.State as P
import Prelude hiding (log)

type MptcpSubflowMapping = [(MptcpSubflow, [(MptcpSubflow, Int)])]

-- data MptcpSubflowMapping

-- | Returns
-- TODO we should sort the returned
mapSubflows :: MptcpConnection -> MptcpConnection -> MptcpSubflowMapping
mapSubflows con1 con2 =
  -- map selectBest (mpconSubflows con1)
  [ (sf1, scoreSubflows sf1) | sf1 <- Set.toList (subflows con1) ]
  where
    -- select best / sortOn
    scoreSubflows sf1 = sortOn (Data.Ord.Down . snd) $
        map (\sf -> (sf, similarityScore sf1 sf)) (Set.toList $ subflows con2)


-- | show a mapping
showMptcpSubflowMapping :: MptcpSubflowMapping -> Text
showMptcpSubflowMapping m =
  T.unlines $ map showOneSfMapping m
  where
    showOneSfMapping (ref, scores) = "Mappings for " <> showMptcpSubflowText ref <> ":\n"
      <> (intercalate "\n-" $ map (\(sf, score) -> showMptcpSubflowText sf <> " SCORE: "<> tshow score) scores)


-- | Ranks the pairings between TCP streams of two different pcaps
-- Returns a list of
mapTcpConnection ::
  -- Members '[Log String, P.State MyState, Cache, Embed IO] r =>
  FrameFiltered TcpConnection Packet
  -> Frame Packet
  -> [(TcpConnection, Int)]
  -- ^ (connection, score)
mapTcpConnection aframe frame = let
      streamsToCompare = getTcpStreams frame
      consToCompare = map (buildTcpConnectionFromStreamId frame) (getTcpStreams frame)
      scores = map (evalScore (ffCon aframe)) (rights consToCompare)
      sortedScores = sortOn (Data.Ord.Down . snd) scores
      evalScore con1 (FrameTcp con2 _) = (con2, similarityScore con1 con2)
    in
      sortedScores

-- |
-- map_mptcp_connection_from_known_streams
mapMptcpConnection ::
  FrameFiltered MptcpConnection Packet
  -> Frame Packet
  -> [(MptcpConnection, Int)]
  -- ^ (connection, score)
mapMptcpConnection aframe frame = let
      streamsToCompare = getMptcpStreams frame
      consToCompare = map (buildMptcpConnectionFromStreamId frame) (getMptcpStreams frame)
      scores = map (evalScore (ffCon aframe)) (rights consToCompare)
      sortedScores = sortOn (Data.Ord.Down . snd) scores
      -- sortedScores = reverse $ sortOn snd scores
      evalScore con1 (FrameTcp con2 _) = (con2, similarityScore con1 con2)
    in
      sortedScores
