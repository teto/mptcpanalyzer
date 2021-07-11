{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}
module MptcpAnalyzer.Commands.Plot
where

import MptcpAnalyzer.Types
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Plots.Types
import MptcpAnalyzer.Cache
-- import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.PlotOWD
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Loader
import Tshark.Fields (baseFields, TsharkFieldDesc (tfieldLabel))
import MptcpAnalyzer.Debug
import Net.Tcp
import Net.Mptcp

import Prelude hiding (filter, lookup, repeat, log)
import Options.Applicative
import Frames
import Frames.CSV

-- import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
-- import Graphics.Rendering.Chart.Easy

import Graphics.Rendering.Chart.Easy hiding (argument)
import Graphics.Rendering.Chart.Backend.Cairo
import Data.Word (Word8, Word16, Word32, Word64)

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
import System.Process hiding (runCommand)
import System.Exit
-- import Data.Time.LocalTime
import Data.Foldable (toList)
import Data.Maybe (fromMaybe, isJust)
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Directory (renameFile)
import System.IO (Handle)
import Frames.ShowCSV (showCSV)
import qualified Data.Set as Set
import Debug.Trace
import Text.Read (readEither)
import qualified Data.Map as Map
import Data.String
import Data.Vinyl.TypeLevel
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


parserPlotSettings :: Bool -> Parser PlotSettings
parserPlotSettings mptcpPlot = PlotSettings 
    <$> optional (strOption
      ( long "out" <> short 'o'
      <> help "Save filename of the plot."
      <> metavar "OUT" ))
    -- <*> optional ( strOption
      -- ( long "title" <> short 't'
      -- <> help "Overrides the default plot title."
      -- <> metavar "TITLE" ))
    -- <*> optional (switch
      -- ( long "primary"
      -- <> help "Copy to X clipboard, requires `xsel` to be installed"
      -- ))
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
    -- <*> (switch
    --   ( long "protocol"
    --   <> help "Uses xdg-open to display plot"
    --   ))


-- |
-- @param 
-- TODO specialize ArgsPlots for TCP ?
piPlotTcpMainParser :: ParserInfo CommandArgs
piPlotTcpMainParser = info parserPlotTcpMain
  ( progDesc " TCP Plots"
  )

-- -> Bool -- ^ for mptcp yes or no
parserPlotTcpMain :: Parser CommandArgs
parserPlotTcpMain  = ArgsPlotGeneric <$> parserPlotSettings False
    <*> hsubparser (
      command "attr" (info (plotStreamParser validTcpAttributes False)
          (progDesc "toto"))
      <> command "owd" piPlotTcpOwd
      )


parserPlotMptcpMain :: Parser CommandArgs
parserPlotMptcpMain  = ArgsPlotGeneric <$> parserPlotSettings False
    <*> hsubparser (
      command "attr" (info (plotStreamParser validTcpAttributes False) (progDesc "toto"))
      <> command "owd" (info (plotParserOwd True) (progDesc "Plot MPTCP owd"))
      )

-- shared by tcp / mptcp
-- parserPlotGeneric :: Parser ArgsPlots
-- parserPlotGeneric  = plotStreamParser validTcpAttributes False
      -- <*> option auto (
      --     metavar "MPTCP"
      --   -- internal is stronger than --belive, hides from all descriptions
      --   <> internal
      --   <> Options.Applicative.value mptcpPlot
      --   <> help ""
      -- )

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

-- data TcpAttr = 

-- Superset of @validTcpAttributes@
validMptcpAttributes :: [String]
validMptcpAttributes = validTcpAttributes
-- |Options that are available for all parsers
-- plotParserGenericOptions 
-- TODO generate from the list of fields, via TH?

validTcpAttributes :: [String]
validTcpAttributes = map T.unpack (Map.keys $ Map.mapMaybe tfieldLabel baseFields)
-- [
--   "tsval"
--   , "rwnd"
--   , "tcpSeq"
--   , "tcpAck"
--   ]

-- type ValidAttributes = [String]


-- TODO pass valid
validateField :: [String] -> ReadM String
validateField validFields = eitherReader $ \arg -> if elem arg validFields then
  Right arg
  else Left $ validationErrorMsg validFields arg

validationErrorMsg :: [String] -> String -> String
validationErrorMsg validFields entry = "validatedField: incorrect value `" ++ entry ++ "` choose from:\n -" ++ intercalate "\n - " validFields


-- readStreamId :: ReadM (StreamId a)
-- readStreamId = eitherReader $ \arg -> case reads arg of
--   [(r, "")] -> return $ StreamId r
--   _ -> Left $ "readStreamId: cannot parse value `" ++ arg ++ "`"

-- TODO pass the list of accepted attributes (so that it works for TCP/MPTCP)
plotStreamParser ::
    [String]
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
      -- auto readStreamId
      <*> argument auto (
          metavar "STREAM_ID"
          <> help "Stream Id (tcp.stream)"
      )
      -- TODO validate as presented in https://github.com/pcapriotti/optparse-applicative/issues/75
      --validate :: (a -> Either String a) -> ReadM a -> ReadM a
      <*> argument (validateField _validAttributes) (
          metavar "TCP_ATTR"
          <> help "A TCP attr in the list: "
      )
      -- TODO ? if nothing prints both directions
      <*> optional (argument readConnectionRole (
          metavar "Destination"
        -- <> Options.Applicative.value RoleServer
        <> help ""
      ))
      -- <*> option auto (
      --     metavar "MPTCP"
      --   -- internal is stronger than --belive, hides from all descriptions
      --   <> internal
      --   <> Options.Applicative.value mptcpPlot
      --   <> help ""
      -- )
      <**> helper

-- | A typeclass abstracting the functions we need
-- to be able to plot against an axis of type a
-- class Ord a => PlotValue a where
--     toValue  :: a -> Double
--     fromValue:: Double -> a
--     autoAxis :: AxisFn a

-- instance RealFloat Word32 where

instance PlotValue Word32 where
    toValue  = fromIntegral
    fromValue = truncate . toRational
        -- autoAxis = autoScaledAxis def
    -- autoScaledAxis def
    -- autoAxis = autoScaledIntAxis def
    autoAxis   = autoScaledIntAxis defaultIntAxis

-- called PlotTcpAttribute in mptcpanalyzer
-- todo pass --filterSyn Args fields
-- TODO filter according to destination


-- destinations is an array of destination
cmdPlotTcpAttribute :: (Members [Log, P.State MyState, Cache, Embed IO] m)
  => String -- Tcp attr
  -> FilePath -- ^ temporary file to save plot to
  -> Handle
  -> [ConnectionRole]
  -> FrameFiltered TcpConnection Packet
  -> Sem m RetCode
cmdPlotTcpAttribute field tempPath _ destinations aFrame = do

-- inCore converts into a producer
  -- embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
  -- embed $ writeCSV "debug.csv" frame2
  embed $ toFile def tempPath $ do
      layout_title .= "TCP " ++ field
      -- TODO generate for mptcp plot
      mapM_ plotAttr destinations

  return Continue
  where
    -- filter by dest
    frame2 = addTcpDestinationsToAFrame aFrame
    plotAttr dest =
        plot (line ("TCP " ++ field ++ " (" ++ show dest ++ ")") [ [ (d,v) | (d,v) <- zip timeData seqData ] ])
        where
          -- frameDest = ffTcpFrame tcpFrame
          frameDest = frame2
          unidirectionalFrame = filterFrame (\x -> x ^. tcpDest == dest) (ffFrame frameDest)

          seqData :: [Double]
          -- seqData = map fromIntegral (toList $ (getSelector field) <$> unidirectionalFrame)
          seqData = getData unidirectionalFrame field
          timeData = toList $ view relTime <$> unidirectionalFrame

          -- selector
          -- type Lens s t a b = forall f. Functor f => (a -> f b) -> s -> f t
          -- selector :: String -> Lens s t a b

-- TODO it should be capabale of returning
-- getSelector :: forall a. a -> Double
-- Getter
-- use / view

-- type HostCols = RecordColumns HostCols


-- it should be possible to get something more abstract
getData :: forall t a2. (Num a2,
            -- RecElem
            --   Rec TcpLen TcpLen rs rs (Data.Vinyl.TypeLevel.RIndex TcpLen rs),
            -- (Record HostCols) <: (Record rs)
            Foldable t, Functor t) =>
            t (Record (TcpDest ': HostCols) ) -> String -> [a2]
getData frame attr =
  toList (getAttr  <$> frame)
  where
    getAttr = case attr of
      "tcpSeq" -> fromIntegral . view tcpSeq
      "tcpLen" -> fromIntegral. view tcpLen
      "rwnd" -> fromIntegral. view rwnd
      "tcpAck" -> fromIntegral. view tcpAck
      -- "tsval" -> tsval
      _ -> error "unsupported attr"

-- type Lens s t a b
-- case
cmdPlotMptcpAttribute :: (Members [Log, P.State MyState, P.Trace, Cache, Embed IO] m) =>
    String -- Tcp attr
    -> FilePath -- ^ temporary file to save plot to
    -> Handle
    -> [ConnectionRole]
    -> FrameFiltered MptcpConnection Packet
    -> Sem m RetCode
cmdPlotMptcpAttribute field tempPath _ destinations aFrame = do

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
      mapM_ plotAttr ( [ (x, y) | x <- destinations , y <- Set.toList $ mpconSubflows $ ffCon aFrame ])
      -- mapM_ plotAttr destinations

  return Continue
  where
    -- add dest to the whole frame
    frameDest = addMptcpDest (ffFrame aFrame) (ffCon aFrame)
    plotAttr (dest, sf) =
      plot (line lineLabel [ [ (d,v) | (d,v) <- zip timeData seqData ] ])

        where
          -- show sf
          lineLabel = "subflow " ++ show (conTcpStreamId (sfConn sf))  ++ " seq (" ++ show dest ++ ")"
          -- frameDest = frame2
          unidirectionalFrame = filterFrame (\x -> x ^. mptcpDest == dest
                    && x ^. tcpStream == conTcpStreamId (sfConn sf) ) frameDest

          seqData :: [Double]
          seqData = map fromIntegral (toList $ view tcpSeq <$> unidirectionalFrame)
          timeData = traceShow ("timedata" ++ show (frameLength unidirectionalFrame)) toList $ view relTime <$> unidirectionalFrame


