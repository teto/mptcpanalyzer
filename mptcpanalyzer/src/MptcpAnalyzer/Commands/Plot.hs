{-|
Module: MptcpAnalyzer.Commands.Plot
Maintainer  : matt
License     : GPL-3


-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE StandaloneDeriving #-}
module MptcpAnalyzer.Commands.Plot (
  -- * Actual commands that plot
    cmdPlotMptcpAttribute
  , cmdPlotTcpAttribute

  -- * parsers
  , piPlotTcpMainParser
  , parserPlotTcpMain
  , parserPlotTcpLive
  , parserPlotMptcpLive
  , parserPlotMptcpMain
)
where

-- from mptcpanalyzer
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Plots.Types
import MptcpAnalyzer.Types
import MptcpAnalyzer.Utils.Completion (completePath, readFilename)
-- import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.PlotOWD
import MptcpAnalyzer.Debug
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Utils.Text
import Net.IP
import Net.Mptcp
import Net.Tcp
import Tshark.Fields (TsharkFieldDesc(tfieldLabel), baseFields)
-- import Net.IPv4

-- hackage
import Frames
import Frames.CSV
import Options.Applicative
import Prelude hiding (filter, log, lookup, repeat)

-- import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
-- import Graphics.Rendering.Chart.Easy

import Data.Vinyl (ElField(..), Rec(..), rapply, rmapX, xrec)
import Data.Vinyl.Class.Method
import Data.Word (Word16, Word32, Word64, Word8)
import Graphics.Rendering.Chart.Backend.Cairo (toFile)
import Graphics.Rendering.Chart.Easy hiding (argument)

import Data.List (filter, intercalate)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Pipes as P
import qualified Pipes.Prelude as P
import Polysemy
import qualified Polysemy as P
import Polysemy.State as P
import Polysemy.Trace as P
-- import Colog.Polysemy (Log, log)
import System.Exit
import System.Process hiding (runCommand)
-- import Data.Time.LocalTime
-- import Data.Foldable (toList)
import qualified Data.Foldable as F
import qualified Data.Map as Map
import Data.Maybe (catMaybes, fromMaybe, isJust, maybeToList)
import qualified Data.Set as Set
import Data.String
import Data.Time
import Data.Vinyl.TypeLevel
import Debug.Trace
import Distribution.Simple.Utils (TempFileOptions(..), withTempFileEx)
import Frames.ShowCSV (showCSV)
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import System.Directory (renameFile)
import System.IO (Handle)
import Text.Read (readEither)

-- import Data.Time.Calendar
import Data.Time.LocalTime
import MptcpAnalyzer.Stream

mkDate :: Integer -> LocalTime
mkDate jday =
  LocalTime (ModifiedJulianDay jday) midnight

-- Plot MPTCP subflow attributes over time

-- | Parses options common to all plots like the title
parserPlotSettings :: Bool -> Parser PlotSettings
parserPlotSettings mptcpPlot = PlotSettings
    <$> optional (strOption
      ( long "out" <> short 'o'
      <> help "Save filename of the plot."
      <> metavar "OUT" ))
    <*> optional ( strOption
      ( long "title" <> short 't'
      <> help "Overrides the default plot title."
      <> metavar "TITLE" ))
    <*> switch ( long "display" <> help "Uses xdg-open to display plot")
    <*> option auto (
          metavar "MPTCP"
        -- internal is stronger than --belive, hides from all descriptions
        <> internal
        <> Options.Applicative.value mptcpPlot
        <> help ""
      )


-- |
-- @param
-- TODO specialize ArgsPlots for TCP ?
piPlotTcpMainParser :: ParserInfo CommandArgs
piPlotTcpMainParser = info parserPlotTcpMain
  ( progDesc " TCP Plots"
  )


--
parserLivePlotTcpSettings :: Parser LivePlotTcpSettings
parserLivePlotTcpSettings = LivePlotTcpSettings <$>
    parserConnection
    <*> optional (strOption
      ( long "fake" <> short 'f'
      <> help "Load data from a pcap. This is used only for testing."
      <> completer completePath
      <> metavar "PCAP" ))
    <*> optional (parserDestinationRole)
  <*> strArgument (
    metavar "interface" <> help "interface to monitor"
    -- TODO fetch list of interfaces in advance !
    <> completeWith ["eno1"]
    )

-- loadConnectionsFromFile
plotLiveFilter :: Parser ArgsPlots
plotLiveFilter = ArgsPlotLiveTcp <$> parserLivePlotTcpSettings


-- |Helper to load an IP
readIP :: ReadM IP
-- encode or decode available, IP has
readIP = eitherReader $ \arg -> case decode $ T.pack arg of
    Just ip -> Right ip
    _otherwise -> Left $ "Could not decode ip " ++ arg

parserConnection :: Parser TcpConnection
parserConnection = TcpConnection <$>
  argument readIP (metavar "CLIENT_IP" <> help "Client IP (v4 or v6)")
  <*> argument readIP (metavar "SERVER_IP" <> help "Server IP (v4 or v6)")
  <*> argument auto (metavar "CLIENT_PORT" <> help "Client port")
  <*> argument auto (metavar "SERVER_PORT" <> help "Server port")
  -- Stream id wont be used anyway
  <*> pure (StreamId 0)
  -- <*> strArgument ( metavar "interface" <> help "interface to monitor")

parserPlotTcpLive :: Parser CommandArgs
parserPlotTcpLive  = ArgsPlotGeneric <$> parserPlotSettings False
    <*> (plotLiveFilter)

parserPlotMptcpLive :: Parser CommandArgs
parserPlotMptcpLive  = ArgsPlotGeneric <$> parserPlotSettings False
    <*> (ArgsPlotLiveMptcp <$> parserLivePlotTcpSettings)


-- -> Bool -- ^ for mptcp yes or no
parserPlotTcpMain :: Parser CommandArgs
parserPlotTcpMain  = ArgsPlotGeneric <$> parserPlotSettings False
    <*> hsubparser (
      command "attr" (info (plotStreamParser validTcpAttributes False)
          (progDesc "toto"))
      <> command "owd" piPlotTcpOwd
      )


parserPlotMptcpMain :: Parser CommandArgs
parserPlotMptcpMain  = ArgsPlotGeneric <$> parserPlotSettings True
    <*> hsubparser (
      command "attr" (info (plotStreamParser validTcpAttributes True)
          (progDesc "Plot MPTCP attribute (choose from ...)"))
      <> command "owd" (info (plotParserOwd True) (progDesc "Plot MPTCP owd"))
      )

-- piPlotTcpAttrParser :: ParserInfo ArgsPlots
-- piPlotTcpAttrParser = info (plotStreamParser validTcpAttributes False)
--   ( progDesc "Plot TCP attr"
--   )

-- |
-- @param
piPlotMptcpParser :: ParserInfo ArgsPlots
piPlotMptcpParser = info (
  plotStreamParser validMptcpAttributes True
  )
  ( progDesc "Plot MPTCP attr"
  )


-- Superset of @validTcpAttributes@
validMptcpAttributes :: [String]
validMptcpAttributes = validTcpAttributes
-- |Options that are available for all parsers
-- plotParserGenericOptions
-- TODO generate from the list of fields, via TH?

validTcpAttributes :: [String]
validTcpAttributes = map T.unpack (Map.keys $ Map.mapMaybe tfieldLabel baseFields)


validateField :: [String] -> ReadM String
validateField validFields = eitherReader $ \arg -> if elem arg validFields then
  Right arg
  else Left $ validationErrorMsg validFields arg

validationErrorMsg :: [String] -> String -> String
validationErrorMsg validFields entry = "validatedField: incorrect value `" ++ entry ++ "` choose from:\n -" ++ intercalate "\n - " validFields


parserDestinationRole :: Parser ConnectionRole
parserDestinationRole = argument readConnectionRole (
          metavar "Destination"
        -- <> Options.Applicative.value RoleServer
        <> help "Only show in a specific direction"
        <> completeWith ["server", "client"]
      )

-- TODO pass the list of accepted attributes (so that it works for TCP/MPTCP)
plotStreamParser ::
       [String]
    -- ^ List of TCP attribute names
    -> Bool -- ^ for mptcp yes or no
    -> Parser ArgsPlots
plotStreamParser _validAttributes mptcpPlot = ArgsPlotTcpAttr <$>
      -- this ends up being not optional !
      -- argument (validateField _validAttributes) (
      --     metavar "FIELD"
      --     <> help ( "Field to plot (choose from " ++ (intercalate ", " _validAttributes) ++ ")")
      -- )
      strArgument (
          metavar "PCAP"
          <> help "File to analyze"
      )
      <*> argument auto (
          metavar "STREAM_ID"
          <> help "Stream Id (tcp.stream)"
      )
      -- TODO validate as presented in https://github.com/pcapriotti/optparse-applicative/issues/75
      <*> argument (validateField _validAttributes) (
          metavar "TCP_ATTR"
          <> help ("A TCP attr in the list: " <> (unlines validTcpAttributes))
          <> completeWith _validAttributes
      )
      -- TODO ? if nothing prints both directions
      <*> optional (parserDestinationRole)
      <**> helper

-- | A typeclass abstracting the functions we need
-- to be able to plot against an axis of type a
-- class Ord a => PlotValue a where
--     toValue  :: a -> Double
--     fromValue:: Double -> a
--     autoAxis :: AxisFn a

-- instance RealFloat Word32 where

-- deriving instance PlotValue Word32
instance PlotValue Word32 where
    -- => toDouble
    toValue  = fromIntegral
    -- => double -> value
    fromValue = truncate . toRational
        -- autoAxis = autoScaledAxis def
    -- autoScaledAxis def
    -- autoAxis = autoScaledIntAxis def
    autoAxis   = autoScaledIntAxis defaultIntAxis

instance PlotValue Word64 where
    -- => toDouble
    toValue  = fromIntegral
    -- => double -> value
    fromValue = truncate . toRational
        -- autoAxis = autoScaledAxis def
    -- autoScaledAxis def
    -- autoAxis = autoScaledIntAxis def
    autoAxis   = autoScaledIntAxis defaultIntAxis

-- called PlotTcpAttribute in mptcpanalyzer
-- todo pass --filterSyn Args fields
-- TODO filter according to destination


-- | Plots the selected attribute
-- ![image description](pathtoimage.png)

cmdPlotTcpAttribute :: (
  Members [Log, P.State MyState, Cache, Embed IO] m
  )
  => String -- ^Tcp attribute see @validTcpAttributes@
  -- -> FilePath -- ^ temporary file to save plot to
  -> [ConnectionRole]
  -> FrameFiltered TcpConnection Packet
  -- we could return a EC r () instead
  -> Sem m (EC (Layout Double Double) ())
cmdPlotTcpAttribute field destinations aFrame = do

-- inCore converts into a producer
  -- embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
  -- embed $ writeCSV "debug.csv" frame2
  -- TODO provide a nice label
  -- TODO generate for mptcp plot
  return $ do
    layout_title .= "TCP " ++ field
    mapM_ plotAttr destinations

  -- return Continue
  where
    -- filter by dest
    frame2 = addTcpDestinationsToAFrame aFrame
    -- plotAttr :: ( PlotValue y) => ConnectionRole -> EC (Layout Double y) ()
    plotAttr dest =
        plot (line ("TCP " ++ field ++ " (" ++ show dest ++ ")") [ [ (d,v) | (d,v) <- plotData ] ])
        -- plot (line ("TCP " ++ field ++ " (" ++ show dest ++ ")") [ my_data ])
        where
          -- frameDest = ffTcpFrame tcpFrame
          frameDest = frame2
          unidirectionalFrame = filterFrame (\x -> x ^. tcpDest == dest) (ffFrame frameDest)

          plotData :: [(Double, Double)]
          plotData = getData (unidirectionalFrame') field

          -- we add a fake mptcpDest column to satisfy
          unidirectionalFrame' = fmap (\x -> Col RoleServer :& x) unidirectionalFrame
          -- (timeData, seqData) = plotData


-- it should be possible to get something more abstract
getData ::
            -- RecElem
            --   Rec TcpLen TcpLen rs rs (Data.Vinyl.TypeLevel.RIndex TcpLen rs),
            -- (Record HostCols) <: (Record rs)
            -- Foldable t, Functor t
            FrameRec (MptcpDest ': TcpDest ': HostCols) -> String -> [(Double, Double)]
getData frame attr =
  getAttr
  where
    -- timeData :: [Double]
    timeData = F.toList $ view relTime <$> frame

    getAttr = case attr of
      "tcpSeq" -> [ (t, v) | (t, v) <- zip timeData (getTcpData tcpSeq) ]
      -- "tcpLen" -> fromIntegral. view tcpLen
      -- "rwnd" -> fromIntegral. view rwnd
      -- "tcpAck" -> fromIntegral. view tcpAck
      -- "tsval" -> tsval
      "mptcpDsn" -> getMptcpData frame mptcpDsn
      "mptcpDack" -> getMptcpData frame mptcpDack

      _          -> error "unsupported attr"

    -- getTcpData  t (Record (TcpDest ': HostCols) )  ::
    -- getTcpData  frame' getter = F.toList $ (fromIntegral . view getter) <$> frame'

    getTcpData getter = F.toList ((fromIntegral . view getter) <$> frame)

getMptcpData :: _
getMptcpData frame getter =
  [ (t, v) | (t, v) <- zip timeData values ]
  -- (timeData, view relTime <$> justFrame)
  where
    timeData = F.toList $ view relTime <$> justFrame
    values = fmap fromIntegral $ catMaybes $ F.toList $ (view getter) <$> justFrame
    -- filter on the field
    justFrame = filterFrame (\x -> isJust $ x ^. getter) frame


-- | Plot an attribute selected from ''
-- @TODO support more attributes
cmdPlotMptcpAttribute :: (
  Members [
    Log, P.State MyState, P.Trace, Cache, Embed IO
  ] m) => String -- ^ mptcp attr
    -> FilePath -- ^ temporary file to save plot to
    -> [ConnectionRole]
    -> FrameFiltered MptcpConnection Packet
    -> Sem m RetCode
cmdPlotMptcpAttribute field tempPath destinations aFrame = do

-- inCore converts into a producer
  Log.debug $ "show con " <> tshow (ffCon aFrame)
  P.trace $ T.unpack $ showConnectionText (ffCon aFrame)
  P.trace $ "number of packets" ++ show (frameLength (ffFrame aFrame))
  -- TODO remove
  embed $ writeCSV "debug.csv" (ffFrame aFrame)
  embed $ writeCSV "dest.csv" frameDest
  embed $ toFile def tempPath $ do
      layout_title .= "MPTCP " ++ field
      -- TODO generate for mptcp plot
      -- for each subflow, plot the MptcpDest
      mapM_ plotAttr ( [ (dest, con) | dest <- destinations , con <- Set.toList $ _mpconSubflows $ ffCon aFrame ])
      -- mapM_ plotAttr destinations

  return Continue
  where
    -- add dest to the whole frame
    frameDest = addMptcpDest (ffFrame aFrame) (ffCon aFrame)
    plotAttr (dest, sf) =
      -- plot (line lineLabel [ [ (d,v) | (d,v) <- zip timeData seqData ] ])
      plot (line lineLabel [ frameData ])
      where
          -- frameData :: ([Double], [
          -- strip down
          frameData = getData unidirectionalFrame field
          -- show sf
          lineLabel = "subflow " ++ show (conTcpStreamId (sfConn sf))  ++ " seq (" ++ show dest ++ ")"
          -- frameDest = frame2
          unidirectionalFrame = filterFrame (\x -> x ^. mptcpDest == dest
                    && x ^. tcpStream == conTcpStreamId (sfConn sf) ) frameDest

          -- seqData :: [Double]
          -- seqData = map fromIntegral (F.toList $ view tcpSeq <$> unidirectionalFrame)
          -- timeData = traceShow ("timedata" ++ show (frameLength unidirectionalFrame)) F.toList $ view relTime <$> unidirectionalFrame


