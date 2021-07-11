{-
Module      : MptcpAnalyzer.Merge
Description : Merges 2 dataframes into a single one with the format sender -> receiver
Maintainer  : matt
-}
{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE DataKinds   #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE PolyKinds           #-}
{-# LANGUAGE GADTs               #-}
{-# LANGUAGE TypeOperators       #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE TypeFamilies        #-}
{-# LANGUAGE TypeOperators       #-}
{-# LANGUAGE TypeApplications    #-}
{-# LANGUAGE Rank2Types          #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module MptcpAnalyzer.Commands.PlotOWD
where

import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Types
import MptcpAnalyzer.Plots.Types
import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Debug
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Merge
-- for retypeColumn
import MptcpAnalyzer.Frames.Utils
-- for fields
import Net.Tcp
import Net.Mptcp

import Prelude hiding (filter, lookup, repeat, log)
import Options.Applicative
import Polysemy
import qualified Polysemy.Trace as P
import Frames
import qualified Frames as F
import Frames.CSV

-- import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
-- import Graphics.Rendering.Chart.Easy

import Graphics.Rendering.Chart.Easy hiding (argument)
import Graphics.Rendering.Chart.Backend.Cairo
import Data.Word (Word8, Word16, Word32, Word64)

import Data.Vinyl.TypeLevel as V --(type (++), Snd)

import Data.Text (Text)
import qualified Data.Text as T
import qualified Pipes as P hiding (embed)
import qualified Pipes.Prelude as P
import Polysemy (Member, Members, Sem, Embed)
import qualified Polysemy as P
import Polysemy.State as P
import System.Process hiding (runCommand)
import System.Exit
-- import Data.Time.LocalTime
import Data.Foldable (toList)
import Data.Maybe (fromMaybe, catMaybes)
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Directory (renameFile)
import System.IO (Handle)
import Frames.ShowCSV (showCSV)
import qualified Data.Set as Set
import Debug.Trace
import GHC.TypeLits (Symbol)
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log

-- data PlotTypes = PlotTcpAttribute {
--     pltAttrField :: Text
--     -- syndrop => drop syn packets
--     -- Drops first 3 packets of the dataframe assuming they are syn
--   }

-- Plot MPTCP subflow attributes over time

-- piPlotParserTcpAttr :: Parser PlotTypes
-- piPlotParserTcpAttr = PlotTcpAttribute <$> argument str
--       ( help "Choose an mptcp attribute to plot"
--       <> metavar "FIELD" )

-- |
-- @param
piPlotTcpOwd ::  ParserInfo ArgsPlots
piPlotTcpOwd = info (plotParserOwd False) (progDesc "Plot TCP owd")



-- TODO pass the list of accepted attributes (so that it works for TCP/MPTCP)
plotParserOwd ::
    -- [String]
    Bool -- ^ for mptcp yes or no
    ->
    Parser ArgsPlots
plotParserOwd _mptcpPlot = ArgsPlotOwdTcp <$>
      parserPcapMapping False
      -- this ends up being not optional !
      -- strArgument (
      --     metavar "PCAP1"
      --     <> help "File to analyze"
      -- )
      -- <*> strArgument (
      --     metavar "PCAP2"
      --     <> help "File to analyze"
      -- )
      -- -- auto readStreamId
      -- <*> argument auto (
      --     metavar "STREAM_ID1"
      --     <> help "Stream Id (tcp.stream)"
      -- )
      -- <*> argument auto (
      --     metavar "STREAM_ID2"
      --     <> help "Stream Id (tcp.stream)"
      -- )
      -- TODO validate as presented in https://github.com/pcapriotti/optparse-applicative/issues/75
      --validate :: (a -> Either String a) -> ReadM a -> ReadM a
      -- TODO ? if nothing prints both directions
      <*> optional (argument readConnectionRole (
          metavar "Destination"
        -- <> Options.Applicative.value RoleServer
        <> help ""
      ))
      -- <**> help
      -- <*> option auto (
      --     metavar "MPTCP"
      --   -- internal is stronger than --belive, hides from all descriptions
      --   <> internal
      --   <> Options.Applicative.value mptcpPlot
      --   <> help ""
      -- )

-- called PlotTcpAttribute in mptcpanalyzer
-- todo pass --filterSyn Args fields
-- TODO filter according to destination

-- destinations is an array of destination
-- cmdPlotTcpAttribute :: Members [Log String,  P.State MyState, Cache, Embed IO] m =>
--           FilePath -- ^ temporary file to save plot to
--           -> Handle
--           -> [ConnectionRole]
--           -> FrameFiltered Packet
--           -> Sem m RetCode
-- cmdPlotTcpAttribute tempPath _ destinations aFrame = do

-- -- inCore converts into a producer
--   -- embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
--   -- embed $ writeCSV "debug.csv" frame2
--   embed $ toFile def tempPath $ do
--       layout_title .= "TCP Sequence number"
--       -- TODO generate for mptcp plot
--       flip mapM_ destinations plotAttr

--   return Continue
--   where
--     -- filter by dest
--     frame2 = addTcpDestinationsToAFrame aFrame
--     plotAttr dest =
--         plot (line ("TCP seq (" ++ show dest ++ ")") [ [ (d,v) | (d,v) <- zip timeData seqData ] ])
--         where
--           -- frameDest = ffTcpFrame tcpFrame
--           frameDest = frame2
--           -- frameDest = frame2
--           unidirectionalFrame = filterFrame (\x -> x ^. tcpDest == dest) (ffFrame frameDest)

--           seqData :: [Double]
--           seqData = map fromIntegral (toList $ view tcpSeq <$> unidirectionalFrame)
--           timeData = toList $ view relTime <$> unidirectionalFrame

-- AbsTime2
-- type AbsTime2 = "absTime2" :-> Text  -- :: (Symbol, *)

-- absTime2 is problematic
-- declareColumn "absTime2" ''Text
-- declareColumn "absTimeSnd" ''Double
-- type AbsTime2 = "absTime2" :-> Text  -- :: (Symbol, *)
-- expects (Symbol, Symbol, Type)
-- type AbsTimeRenameTest =   ("absTime" :: Symbol, "absTime2", Text)

-- type RetypeMatt = [
--   ("absTime", "absTime2", Text)
--   ]

cmdPlotTcpOwd :: (Members [Log, P.Trace, P.State MyState, Cache, Embed IO] m)
  => FilePath -- ^ temporary file to save plot to
  -> Handle
  -> [ConnectionRole]
  -- -> TcpConnection
  -> (PcapMapping Tcp)
  -- -> MergedFrame
  -- -> FrameFiltered Packet
  -- -> FrameFiltered (Record HostColsPrefixed)
  -> Sem m RetCode
cmdPlotTcpOwd tempPath _ destinations (PcapMapping pcap1 streamId1 pcap2 streamId2) = do
  Log.info "plotting TCP OWDs "
  -- look at https://hackage.haskell.org/package/vinyl-0.13.0/docs/Data-Vinyl-Functor.html#t::.
  -- could use showRow as well
  -- P.embed $ dumpRec $ head justRecs
  -- P.trace $ "There are " ++ show (length justRecs) ++ " valid merged rows (out of " ++ show (length mergedRes) ++ " merged rows)"
  -- P.trace $ (concat . showFields) (head justRecs)
  -- P.embed $ putStrLn $ "retyped column" ++ (concat . showFields) (newCol)
  Log.info $ "plotting owd for tcp.stream " <> tshow streamId1 <> " and " <> tshow streamId2
  eframe1 <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap1 streamId1
  eframe2 <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap2 streamId2

  res <- case (eframe1, eframe2 ) of
    (Left err, _) -> return $ CMD.Error err
    (_, Left err) -> return $ CMD.Error err
    (Right (FrameTcp con frame1), Right aframe2) -> do
        -- TODO addTcpDest -> convert then
        let
          dest = genTcpDestFrame frame1 con

          convertCols' :: Record '[TcpDest] -> Record '[SenderDest]
          convertCols' = F.withNames . F.stripNames
          sendFrame = fmap convertCols' dest

        mergedRes <- mergeTcpConnectionsFromKnownStreams (FrameTcp con (F.zipFrames sendFrame frame1)) aframe2
        -- let mbRecs = map recMaybe mergedRes
        -- let justRecs = catMaybes mbRecs
        let sndRcvFrame = convertToSenderReceiver mergedRes

        embed $ toFile def tempPath $ do
            layout_title .= "TCP One-way delays"
            -- TODO generate for mptcp plot
            -- for each subflow, plot the MptcpDest
            mapM_ (plotAttr sndRcvFrame)  [ x | x <- destinations]


        -- embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
        -- embed $ writeDSV defaultParserOptions "tcp-owd-debug.csv" (toFrame justRecs)
        embed $ writeDSV defaultParserOptions "tcp-owd-converted.csv" sndRcvFrame
        -- P.embed $ putStrLn $ "OWDs:" ++ show owd
        -- so for now we assume an innerJoin (but fix it later)
        return Continue
        where
          -- mbRecs = map recMaybe mergedRes
          -- justRecs = catMaybes mbRecs
          dumpRec x = print x
          -- add dest to the whole frame
          -- frameDest = addMptcpDest (ffFrame aFrame) (ffCon aFrame)
          plotAttr sndRcvFrame dest =
            plot (line lineLabel [ [ (d,v) | (d,v) <- zip timeData owd ] ])

              where
                lineLabel = "TCP seq " ++ showConnection con ++ " (towards " ++ showConnectionRole dest ++ ")"
                unidirectionalFrame = filterFrame (\x -> x ^. senderDest == dest) sndRcvFrame

                timeData = traceShow ("timedata length=" ++ show (frameLength unidirectionalFrame)) toList $ view sndAbsTime <$> unidirectionalFrame

                getOwd x = (x ^. rcvAbsTime) - (x ^. sndAbsTime)

                owd :: [Double]
                owd = let res = map getOwd (toList unidirectionalFrame) in traceShow res res
  return res




cmdPlotMptcpOwd :: (
  Members [Log, P.Trace, P.State MyState, Cache, Embed IO] m)
  => FilePath -- ^ temporary file to save plot to
  -> Handle
  -> [ConnectionRole]
  -> TcpConnection
  -> MergedFrame
  -> Sem m RetCode
cmdPlotMptcpOwd tempPath _ destinations con mergedRes = do
  Log.info "plotting MPTCP OWDs "
  -- look at https://hackage.haskell.org/package/vinyl-0.13.0/docs/Data-Vinyl-Functor.html#t::.
  -- could use showRow as well
  -- P.embed $ dumpRec $ head justRecs
  -- P.trace $ "There are " ++ show (length justRecs) ++ " valid merged rows (out of " ++ show (length mergedRes) ++ " merged rows)"
  -- P.trace $ (concat . showFields) (head justRecs)
  -- P.embed $ putStrLn $ "retyped column" ++ (concat . showFields) (newCol)
  embed $ toFile def tempPath $ do
      layout_title .= "MPTCP One-way delays"
      -- TODO generate for mptcp plot
      -- for each subflow, plot the MptcpDest
      mapM_ plotAttr  [ x | x <- destinations]


  -- embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
  -- embed $ writeDSV defaultParserOptions "mptcp-owd-debug.csv" (toFrame justRecs)
  embed $ writeDSV defaultParserOptions "mptcp-owd-converted.csv" sndRcvFrame
  -- P.embed $ putStrLn $ "OWDs:" ++ show owd
  -- so for now we assume an innerJoin (but fix it later)

  return Continue
  where
    -- mbRecs = map recMaybe mergedRes
    -- justRecs = catMaybes mbRecs
    sndRcvFrame = convertToSenderReceiver mergedRes
    dumpRec x = putStrLn $ show x
    -- add dest to the whole frame
    -- frameDest = addMptcpDest (ffFrame aFrame) (ffCon aFrame)
    plotAttr dest =
      plot (line lineLabel [ [ (d,v) | (d,v) <- zip timeData owd ] ])

        where
          lineLabel = "Subflow DSNs " ++ showConnection con ++ " (towards " ++ showConnectionRole dest ++ ")"
          unidirectionalFrame = filterFrame (\x -> x ^. senderDest == dest) sndRcvFrame

          timeData = traceShow ("timedata length=" ++ show (frameLength unidirectionalFrame)) toList $ view sndAbsTime <$> unidirectionalFrame

          getOwd x = (x ^. rcvAbsTime) - (x ^. sndAbsTime)

          owd :: [Double]
          owd = let res = map getOwd (toList unidirectionalFrame) in traceShow res res


