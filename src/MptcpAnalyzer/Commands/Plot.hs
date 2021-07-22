{-|
Module: MptcpAnalyzer.Commands.Plot
Maintainer  : matt
License     : GPL-3
-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE StandaloneDer:xa #-}
module MptcpAnalyzer.Commands.Plot (
  -- * Actual commands that plot
  cmdPlotMptcpAttribute
  , cmdPlotTcpAttribute

  -- * parsers
  , piPlotTcpMainParser
  , parserPlotTcpMain
  , parserPlotMptcpMain
)
where

import           MptcpAnalyzer.ArtificialFields
import           MptcpAnalyzer.Cache
import           MptcpAnalyzer.Plots.Types
import           MptcpAnalyzer.Types
-- import MptcpAnalyzer.Commands.Definitions
import           MptcpAnalyzer.Commands.Definitions     as CMD
import           MptcpAnalyzer.Commands.PlotOWD
import           MptcpAnalyzer.Debug
import           MptcpAnalyzer.Loader
import           MptcpAnalyzer.Pcap
import           "this" Net.Mptcp
import           "this" Net.Tcp
import           Tshark.Fields                          (TsharkFieldDesc (tfieldLabel), baseFields)

import           Frames
import           Frames.CSV
import           Options.Applicative
import           Prelude                                hiding (filter, log, lookup, repeat)

-- import Graphics.Rendering.Chart.Backend.Diagrams (defaultEnv, runBackendR)
-- import Graphics.Rendering.Chart.Easy

import           Data.Word                              (Word16, Word32, Word64, Word8)
import           Graphics.Rendering.Chart.Backend.Cairo
import           Graphics.Rendering.Chart.Easy          hiding (argument)

import           Data.List                              (filter, intercalate)
import           Data.Text                              (Text)
import qualified Data.Text                              as T
import qualified Pipes                                  as P
import qualified Pipes.Prelude                          as P
import           Polysemy
import qualified Polysemy                               as P
import           Polysemy.State                         as P
import           Polysemy.Trace                         as P
-- import Colog.Polysemy (Log, log)
import           System.Exit
import           System.Process                         hiding (runCommand)
-- import Data.Time.LocalTime
-- import Data.Foldable (toList)
import qualified Data.Foldable                          as F
import qualified Data.Map                               as Map
import           Data.Maybe                             (catMaybes, fromMaybe, isJust, maybeToList)
import qualified Data.Set                               as Set
import           Data.String
import           Data.Vinyl.TypeLevel
import           Debug.Trace
import           Distribution.Simple.Utils              (TempFileOptions (..), withTempFileEx)
import           Frames.ShowCSV                         (showCSV)
import           Polysemy.Log                           (Log)
import qualified Polysemy.Log                           as Log
import           System.Directory                       (renameFile)
import           System.IO                              (Handle)
import           Text.Read                              (readEither)
import           Data.Time

-- import Data.Time.Calendar
import Data.Time.LocalTime

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
        <> help "Only show in a specific direction"
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

deriving instance PlotValue Word32
-- instance PlotValue Word32 where
--     toValue  = fromIntegral
--     fromValue = truncate . toRational
--         -- autoAxis = autoScaledAxis def
--     -- autoScaledAxis def
--     -- autoAxis = autoScaledIntAxis def
--     autoAxis   = autoScaledIntAxis defaultIntAxis

-- called PlotTcpAttribute in mptcpanalyzer
-- todo pass --filterSyn Args fields
-- TODO filter according to destination


-- destinations is an array of destination
cmdPlotTcpAttribute :: (Members [Log, P.State MyState, Cache, Embed IO] m)
  => String -- Tcp attr
  -> FilePath -- ^ temporary file to save plot to
  -> [ConnectionRole]
  -> FrameFiltered TcpConnection Packet
  -> Sem m RetCode
cmdPlotTcpAttribute field tempPath destinations aFrame = do

-- inCore converts into a producer
  -- embed $ putStrLn $ showConnection (ffTcpCon tcpFrame)
  -- embed $ writeCSV "debug.csv" frame2
  -- TODO provide a nice label
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
        -- plot (line ("TCP " ++ field ++ " (" ++ show dest ++ ")") [ my_data ])
        where
          -- frameDest = ffTcpFrame tcpFrame
          frameDest = frame2
          unidirectionalFrame = filterFrame (\x -> x ^. tcpDest == dest) (ffFrame frameDest)

          -- seqData :: [Double]
          -- seqData = map fromIntegral (toList $ (getSelector field) <$> unidirectionalFrame)
          (timeData, seqData)= getData unidirectionalFrame field
          -- (timeData, seqData)
          -- timeData = F.toList $ view relTime <$> unidirectionalFrame

          -- selector
          -- type Lens s t a b = forall f. Functor f => (a -> f b) -> s -> f t
          -- selector :: String -> Lens s t a b

-- TODO it should be capabale of returning
-- getSelector :: forall a. a -> Double
-- Getter
-- use / view

-- type HostCols = RecordColumns HostCols

-- it should return the time data too ?
-- it should be possible to get something more abstract
getData:: (PlotValue a1, PlotValue a2, Foldable t, Functor t) =>
            t (Record (TcpDest ': HostCols) ) -> String 
            -> ([a1], [a2])
            -- ^ Returns a time + value

getData frame attr =
  -- F.toList $ getAttr <$> frame)
  getAttr
  where
    timeData = F.toList $ view relTime <$> frame

    getAttr = case attr of
      "tcpSeq"   -> (timeData, getTcpData frame tcpSeq)
      -- "tcpLen"   -> fromIntegral. view tcpLen
      -- "rwnd"     -> fromIntegral. view rwnd
      -- "tcpAck"   -> fromIntegral. view tcpAck
      -- TODO filter
      -- "mptcpDsn" -> getMptcpData frame (view mptcpDsn)
          -- Nothing ->
      -- "tsval" -> tsval
      _          -> error "unsupported attr"

    getTcpData  frame' getter = F.toList ((fromIntegral . view getter) <$> frame')

getMptcpData  frame getter =
  (timeData, view relTime <$> justFrame)
  where
    timeData = F.toList $ view relTime <$> justFrame

    justFrame = filterFrame (\x -> isJust $ x ^. mptcpDsn) frame


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
      mapM_ plotAttr ( [ (x, y) | x <- destinations , y <- Set.toList $ mpconSubflows $ ffCon aFrame ])
      -- mapM_ plotAttr destinations

  return Continue
  where
    -- add dest to the whole frame
    frameDest = addMptcpDest (ffFrame aFrame) (ffCon aFrame)
    plotAttr (dest, sf) =
      plot (line lineLabel [ [ (d,v) | (d,v) <- zip timeData dsnData ] ])

        where
          -- show sf
          lineLabel = "subflow " ++ show (conTcpStreamId (sfConn sf))  ++ " seq (" ++ show dest ++ ")"
          -- frameDest = frame2
          unidirectionalFrame = filterFrame (\x -> x ^. mptcpDest == dest
                    && x ^. tcpStream == conTcpStreamId (sfConn sf) ) frameDest

          -- seqData :: [Double]
          -- seqData = map fromIntegral (toList $ view tcpSeq <$> unidirectionalFrame)
          toto = mptcpDsn
          dsnData :: [Double]
          dsnData = map fromIntegral (catMaybes $ F.toList $ view toto <$> dsnFrame)

          dsnFrame = filterFrame (\x -> isJust $ x ^. mptcpDsn) unidirectionalFrame

          timeData = traceShow ("timedata" ++ show (frameLength unidirectionalFrame)) F.toList $ view relTime <$> dsnFrame


