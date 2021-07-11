{-
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
module MptcpAnalyzer.Map
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Stream
import Net.Tcp
import Net.Mptcp

import Prelude hiding (log)
import Options.Applicative
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
-- import Colog.Polysemy (Log, log)
import Data.Function (on)
import Data.List (sortBy, sortOn)
import Data.Either (rights, lefts)
import Data.Ord
import Frames
import qualified Data.Set as Set
import Data.Text (intercalate, Text)

type MptcpSubflowMapping = [(MptcpSubflow, [(MptcpSubflow, Int)])]

-- data MptcpSubflowMapping 

-- | Returns
-- TODO we should sort the returned
mapSubflows :: MptcpConnection -> MptcpConnection -> MptcpSubflowMapping
mapSubflows con1 con2 =
  -- map selectBest (mpconSubflows con1)
  [ (sf1, scoreSubflows sf1) | sf1 <- Set.toList (mpconSubflows con1) ]
  where
    -- select best / sortOn
    scoreSubflows sf1 = sortOn (Data.Ord.Down . snd) $
        map (\sf -> (sf, similarityScore sf1 sf)) (Set.toList $ mpconSubflows con2)


showMptcpSubflowMapping :: MptcpSubflowMapping -> Text
showMptcpSubflowMapping m =
  intercalate "\n" $ map showOneSfMapping m
  where
    showOneSfMapping (ref, scores) = "Mappings for " <> showMptcpSubflowText ref <> ":\n"
      <> (intercalate "\n-" $ map (\(sf, score) -> showMptcpSubflowText sf <> " SCORE: "<> tshow score) scores)


-- |
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
