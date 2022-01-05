{-
Module:  MptcpAnalyzer.Commands.Map
Description : Map tcp.stream ids from one pcap to another
Maintainer  : matt
Portability : Linux


* Mapping tcp.stream ids from one pcap to another

-}
module MptcpAnalyzer.Commands.Map (
  mapTcpOpts
  , mapMptcpOpts
  -- , parserMapConnection
  , cmdMapTcpConnection
  , cmdMapMptcpConnection
)
where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.List as CMD
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Map
import MptcpAnalyzer.Merge
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Stream
import MptcpAnalyzer.Types
import MptcpAnalyzer.Utils.Completion (completePath, readFilename)
import MptcpAnalyzer.Utils.Text
import Net.Mptcp

import Options.Applicative
import Polysemy (Embed, Member, Members, Sem)
import qualified Polysemy as P
import Polysemy.State as P
import Polysemy.Trace as P
import Prelude hiding (log)
-- import Colog.Polysemy (Log, log)
import Data.Either (lefts, rights)
import Data.Function (on)
import Data.List (sortBy, sortOn)
import Data.Text (intercalate)
import qualified Data.Text as TS
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import System.Console.ANSI
import System.Console.Haskeline
import Tshark.Main (defaultTsharkPrefs)


mapTcpOpts :: ParserInfo CommandArgs
mapTcpOpts = info (
    (parserMapConnection False) <**> helper)
  ( progDesc "Attempts to map a TCP connection to another one"
  )

mapMptcpOpts :: ParserInfo CommandArgs
mapMptcpOpts = info (
    parserMapConnection True <**> helper)
  ( progDesc "Maps a MPTCP connection to another one"
  )

parserMapConnection :: Bool -> Parser CommandArgs
parserMapConnection forMptcp =
    ArgsMapTcpConnections <$> (
      CommandMapPcap <$>
      strArgument (
          metavar "PCAP1"
          <> completer completePath
          <> help "File to analyze"
      )
      <*> strArgument (
          metavar "PCAP2"
          <> completer completePath
          <> help "File to analyze"
      )
      -- readStreamId
      <*> argument auto (
          metavar "TCP_STREAM"
          <> help "stream id to analyzer"
      )
      <*> switch (
          long "verbose"
          <> help "Verbose or not"
      )
      <*> option auto (
          metavar "LIMIT"
        <> Options.Applicative.value 10

          <> help "Limit the number of comparisons to display"
      )
      )
      <*> option auto (
          metavar "MPTCP"
        -- internal is stronger than --belive, hides from all descriptions
        <> internal
        <> Options.Applicative.value forMptcp
        <> help ""
      )

printInRed :: String -> String
printInRed val = setSGRCode [SetColor Foreground Vivid Red] ++ val ++ setSGRCode [Reset]

-- TODO this could be made polymorphic using StreamConnection
cmdMapTcpConnection, cmdMapMptcpConnection :: (Members '[Log, P.State MyState, P.Trace, Cache, Embed IO] r )
  => CommandMapPcap -> Sem r RetCode
cmdMapTcpConnection (CommandMapPcap pcap1 pcap2 streamId verbose limit) = do
  Log.info "Mapping tcp connections"
  res <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap1 (StreamId streamId)
  res2 <- loadPcapIntoFrame defaultTsharkPrefs pcap2
  case (res, res2) of
    (Right aframe, Right frame) -> do
      let streamsToCompare = (getTcpStreams frame)
      let consToCompare = map (buildTcpConnectionFromStreamId frame) (getTcpStreams frame)
      Log.info $ "Best match for " <> tshow (ffCon aframe) <> " is "
      Log.info $ "Comparing with stream " <> tshow streamsToCompare
      -- TODO sort results and print them
      let sortedScores = mapTcpConnection aframe frame
      -- TODO only display X first take 5
      P.trace $ TS.unpack $ intercalate "\n" $ map displayScore sortedScores
      -- display failures
      P.trace $ TS.unpack $ intercalate "\n" $ map displayFailure (lefts consToCompare)
      return CMD.Continue
      where
        displayScore (con, score) = "Score for connection " <> showConnectionText con
            <> ": " <> TS.pack (printInRed $ show score)
        displayFailure err = "Couldn't compute score for tcp.stream  " <> tshow err
    _ -> return $ CMD.Error "An error happened"

cmdMapMptcpConnection (CommandMapPcap pcap1 pcap2 streamId verbose limit) = do
  Log.info "Mapping mptcp connections"
  res <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap1 (StreamId streamId)
  res2 <- loadPcapIntoFrame defaultTsharkPrefs pcap2
  case (res, res2) of
    (Right aframe, Right frame) -> do
      let streamsToCompare = getMptcpStreams frame
      let consToCompare = map (buildTcpConnectionFromStreamId frame) (getTcpStreams frame)
      Log.info $ "Best match for " <> tshow (ffCon aframe) <> " is "
      Log.debug ("Comparing with stream " <> tshow streamsToCompare)
      -- let scores = map (evalScore (ffCon aframe)) (rights consToCompare)
      -- let sortedScores = (sortOn snd scores)
      let sortedScores = mapMptcpConnection aframe frame
      P.trace $ TS.unpack $ intercalate "\n" $ map displayScore sortedScores
      P.trace $ TS.unpack $ intercalate "\n" $ map displayFailure (lefts consToCompare)
      return CMD.Continue
      where
        evalScore con1 (FrameTcp con2 _) = (con2, similarityScore con1 con2)

        -- setSGRCode [SetColor Foreground Vivid Red] <>
        -- <> setSGRCode [Reset]
        displayScore (con, score) = "Score for connection " <> tshow (mpconStreamId con)
            <> ": " <> tshow score <> "\n" <> showConnectionText con <> "\n"
        displayFailure err = "Couldn't compute score for mptcp.stream " <> tshow err
    _ -> return $ CMD.Error "An error happened"
