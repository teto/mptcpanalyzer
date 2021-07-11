{-|
Description : Mptcpanalyzer
Maintainer  : matt
Stability   : testing
Portability : Linux

 accepts as input(s) capture file(s) (\*.pcap) and depending on from there can :

* list the MPTCP connections in the pcap
* display some statistics on a specific MPTCP connection (list of subflows etc...);
* convert packet capture files (\*.pcap) to \*.csv files
* plot data sequence numbers for all subflows
* `XDG compliance <http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html>`_, i.e., 
  |prog| looks for files in certain directories. will try to load your configuration from `$XDG_CONFIG_HOME/mptcpanalyzer/config`
* caching mechanism: mptcpanalyzer compares your pcap creation time and will
  regenerate the cache if it exists in `$XDG_CACHE_HOME/mptcpanalyzer/<path_to_the_file>`
* support 3rd party plugins (plots or commands)

Most commands are self documented and/or with autocompletion.

Then you have an interpreter with autocompletion that can generate & display plots such as the following:

![Data Sequence Number (DSN) per subflow plot](examples/dsn.png)


-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE LambdaCase             #-}

module Main where

import MptcpAnalyzer.Cache
import MptcpAnalyzer.Types
import MptcpAnalyzer.Stream
import MptcpAnalyzer.ArtificialFields
import MptcpAnalyzer.Commands
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Commands.List as CLI
import MptcpAnalyzer.Commands.ListMptcp as CLI
import MptcpAnalyzer.Commands.Export as CLI
import MptcpAnalyzer.Commands.Map as CLI
import MptcpAnalyzer.Commands.Reinjections as CLI
import MptcpAnalyzer.Merge
import qualified MptcpAnalyzer.Commands.Plot as Plots
import qualified MptcpAnalyzer.Commands.PlotOWD as Plots
import MptcpAnalyzer.Plots.Types
import qualified MptcpAnalyzer.Plots.Owd as Plots
import qualified MptcpAnalyzer.Commands.Load as CL
-- import Control.Monad (void)


import Polysemy (Sem, Members, runFinal, Final)
import qualified Polysemy as P
-- import Polysemy.Reader as P
import qualified Polysemy.IO as P
import qualified Polysemy.State as P
import qualified Polysemy.Embed as P
import qualified Polysemy.Internal as P
-- import qualified Polysemy.Output as P
import qualified Polysemy.Trace as P
import Polysemy.Trace (trace)
import System.FilePath
import System.Directory
import Prelude hiding (concat, init, log)
import Options.Applicative
import Options.Applicative.Help (parserHelp)
-- import Colog.Core.IO (logStringStdout)
-- import Colog.Polysemy (Log)
import Colog.Actions
-- import Graphics.Rendering.Chart.Easy hiding (argument)
import Graphics.Rendering.Chart.Backend.Cairo
import Frames.InCore (toFrame)


-- for noCompletion
        -- <> Options.Applicative.value "/tmp"
import System.Console.Haskeline
import System.Console.ANSI
import Control.Lens ((^.), view)
import System.Exit
import MptcpAnalyzer.Pcap (defaultTsharkPrefs, defaultTsharkOptions, defaultParserOptions)
import Pipes hiding (Proxy)
import System.Process hiding (runCommand)
import Distribution.Simple.Utils (withTempFileEx)
import Distribution.Compat.Internal.TempFile (openTempFile)
import MptcpAnalyzer.Loader
import Data.Maybe (fromMaybe, catMaybes)
import Data.Either (fromLeft)
import Frames.CSV (writeDSV)
import Frames (recMaybe, Frame, Record)
import Frames as F
import System.IO (stderr)
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import Polysemy.Log.Colog (interpretLogStdout)

data CLIArguments = CLIArguments {
  _input :: Maybe FilePath
  , version    :: Bool  -- ^ to show version
  , cacheDir    :: Maybe FilePath -- ^ Folder where to log files
  , logLevel :: Log.Severity   -- ^ what level to use to parse
  , extraCommands :: [String]  -- ^ commands to run on start
  }


loggerName :: String
loggerName = "main"

deriving instance Read Log.Severity

    -- <*> commandGroup "Loader commands"
    -- <> command "load-csv" CL.piLoadCsv

startupParser :: Parser CLIArguments
startupParser = CLIArguments
      <$> optional ( strOption
          ( long "load"
          <> short 'l'
         <> help "Either a pcap or a csv file (in good format).\
                 \When a pcap is passed, mptcpanalyzer will look for a its cached csv.\
                 \If it can't find one (or with the flag --regen), it will generate a \
                 \csv from the pcap with the external tshark program."
         <> metavar "INPUT_FILE" ))
      <*> switch (
          long "version"
          <> help "Show version"
          )
      <*> optional ( strOption
          ( long "cachedir"
         <> help "mptcpanalyzer creates a cache of files in the folder \
            \$XDG_CACHE_HOME/mptcpanalyzer"
         -- <> showDefault
         -- <> Options.Applicative.value "/tmp"
         <> metavar "CACHEDIR" ))
      <*> option auto
          ( long "log-level"
         <> help "Log level"
         <> showDefault
         <> Options.Applicative.value Log.Info
         <> metavar "LOG_LEVEL" )
      -- optional arguments
      <*> many ( argument str (
            metavar "COMMANDS..."
        ))


opts :: ParserInfo CLIArguments
opts = info (startupParser <**> helper)
  ( fullDesc
  <> progDesc "Tool to provide insight in MPTCP (Multipath Transmission Control Protocol)\
              \performance via the generation of stats & plots"
  <> header "hello - a test for optparse-applicative"
  <> footer "You can report issues/contribute at https://github.com/teto/mptcpanalyzer"
  )


-- https://github.com/sdiehl/repline/issues/32

-- just for testing, to remove afterwards
defaultPcap :: FilePath
defaultPcap = "examples/client_2_filtered.pcapng"

        -- P.modify (\s -> s { _prompt = pcapFilename ++ "> ",
        --       _loadedFile = Just frame
        --     })
finalizePrompt :: String -> String
finalizePrompt newPrompt = setSGRCode [SetColor Foreground Vivid Red] ++ newPrompt ++ "> " ++ setSGRCode [Reset]

-- alternatively could modify defaultPrefs
-- subparserInline + multiSuffix helpShowGlobals
defaultParserPrefs :: ParserPrefs
defaultParserPrefs = prefs $ showHelpOnEmpty <> showHelpOnError


-- default if complete = completeFilename,
-- (String, String) -> m (String, [Completion])
customCompleteFunc :: CompletionFunc IO
customCompleteFunc = completeFilename
-- customCompleteFunc _i = return ("toto", [ Completion "toInsert" "choice 1" False ])

main :: IO ()
main = do
  putStrLn "Starting mptcpanalyzer"

  cacheFolderXdg <- getXdgDirectory XdgCache "mptcpanalyzer2"
  -- TODO check if creation fails ?
  -- Create cache if doesn't exist
  doesDirectoryExist cacheFolderXdg >>= \case
      True -> putStrLn ("cache folder already exists" ++ show cacheFolderXdg)
      False -> createDirectory cacheFolderXdg

  let myState = MyState {
    _stateCacheFolder = cacheFolderXdg,
    _loadedFile = Nothing,
    _prompt = finalizePrompt ">"
  }

  options <- execParser opts

  putStrLn "Commands:"
  print $ extraCommands options

  let haskelineSettings = (Settings {
      complete = customCompleteFunc
      , historyFile = Just $ cacheFolderXdg </> "history"
      , autoAddHistory = True
      })
  let
    cacheConfig :: CacheConfig
    cacheConfig = CacheConfig {
      cacheFolder = cacheFolderXdg
      , cacheEnabled = True
    }

  _ <- runInputT haskelineSettings $
          runFinal @(InputT IO)
          $ P.embedToFinal . P.runEmbedded lift
          $ P.traceToIO
          $ P.runState myState
          $ runCache cacheConfig
          $ interpretLogStdout
            (inputLoop (extraCommands options))

      -- -- Set the level of logging we want (for more control see 'filterLogs')
      -- & setLogLevel Debug
  return ()


-- |Global parser: contains every available command
-- TODO for some commands we could factorize the preprocessing eg check a file
-- was pre-loaded
-- aka check the if loadedFile was loaded
-- one can create groups with <|> subparser
mainParser :: Parser CommandArgs
mainParser = subparser (
    commandGroup "Generic"
    <> command "help" helpParser
    <> command "quit" quit
    <> commandGroup "Loader commands"
    <> command "load-csv" CL.piLoadCsv
    <> command "load-pcap" CL.loadPcapOpts
    <> commandGroup "TCP commands"
    <> command "tcp-summary" CLI.piTcpSummaryOpts
    <> command "mptcp-summary" CLI.piMptcpSummaryOpts
    <> command "list-tcp" CLI.piListTcpOpts
    <> command "map-tcp" CLI.mapTcpOpts
    <> command "map-mptcp" CLI.mapMptcpOpts
    <> commandGroup "MPTCP commands"
    <> command "list-reinjections" CLI.piListReinjections
    <> command "list-mptcp" CLI.listMpTcpOpts
    <> command "export" CLI.parseExportOpts
    <> command "analyze" CLI.piQualifyReinjections
    -- <> commandGroup "TCP plots"
    -- TODO here we should pass a subparser
    -- <> subparser (
    -- Main.piParserGeneric
    <> command "plot-tcp" ( info Plots.parserPlotTcpMain (progDesc "hello"))
    <> command "plot-mptcp" ( info Plots.parserPlotMptcpMain (progDesc "hello"))
    )
    where
      helpParser = info (pure ArgsHelp) (progDesc "Display help")
      quit = info (pure ArgsQuit) (progDesc "Quit mptcpanalyzer")


-- |Main parser
mainParserInfo :: ParserInfo CommandArgs
mainParserInfo = info (mainParser <**> helper)
  ( fullDesc
  <> progDesc "Tool to provide insight in MPTCP (Multipath Transmission Control Protocol)\
              \performance via the generation of stats & plots"
  <> header "hello - a test for optparse-applicative"
  <> footer "You can report issues/contribute at https://github.com/teto/mptcpanalyzer"
  )





runCommand :: (Members '[Log, Cache, P.Trace, P.State MyState, P.Embed IO] r)
  => CommandArgs -> Sem r CMD.RetCode
runCommand (ArgsLoadPcap fileToLoad) = loadPcap fileToLoad
  -- ret <- CL.loadPcap fileToLoad
  -- TODO modify only on success
  -- P.modify (\s -> s { _prompt = pcapFilename ++ "> ",
  --       _loadedFile = Just frame
  --     })
  -- return ret
runCommand (ArgsLoadCsv csvFile) = CL.loadCsv csvFile
runCommand (ArgsParserSummary detailed streamId) = CLI.cmdTcpSummary streamId detailed
runCommand (ArgsMptcpSummary detailed streamId) = CLI.cmdMptcpSummary streamId detailed
runCommand (ArgsListSubflows detailed) = CLI.cmdListSubflows detailed
runCommand (ArgsListReinjections streamId)  = CLI.cmdListReinjections streamId
runCommand (ArgsListTcpConnections detailed) = CLI.cmdListTcpConnections detailed
runCommand (ArgsListMpTcpConnections detailed) = CLI.cmdListMptcpConnections detailed
runCommand (ArgsExport out) = CLI.cmdExport out
runCommand (ArgsPlotGeneric plotSettings plotArgs) = runPlotCommand plotSettings plotArgs
runCommand (ArgsMapTcpConnections cmd False) = CLI.cmdMapTcpConnection cmd
runCommand (ArgsMapTcpConnections args True) = CLI.cmdMapMptcpConnection args
runCommand (ArgsQualifyReinjections mapping verbose) = CLI.cmdQualifyReinjections mapping [RoleServer] verbose
runCommand ArgsQuit = cmdQuit
runCommand ArgsHelp = cmdHelp

-- TODO move commands to their own module
-- TODO it should update the loadedFile in State !
-- handleParseResult
-- loadPcap :: CMD.CommandCb
-- loadPcap :: Members [Log, P.State MyState, Cache, Embed IO] m => [String] -> Sem m RetCode
loadPcap :: (Members '[Log, P.State MyState, Cache, P.Embed IO] r)
  => FilePath -- ^ File to load
  -> Sem r RetCode
loadPcap pcapFilename = do
    Log.info $ "loading pcap " <> tshow pcapFilename
    mFrame <- loadPcapIntoFrame defaultTsharkPrefs pcapFilename
    -- fmap onSuccess mFrame
    case mFrame of
      Left _ -> return CMD.Continue
      Right frame -> do
        P.modify (\s -> s {
            _prompt = finalizePrompt pcapFilename,
            _loadedFile = Just frame
          })
        Log.info "Frame loaded" >> return CMD.Continue

-- | Quits the program
cmdQuit :: Members '[P.Trace] r => Sem r CMD.RetCode
cmdQuit = trace "Thanks for flying with mptcpanalyzer" >> return CMD.Exit

-- | Prints the help when requested
cmdHelp :: Members '[P.Trace, P.State MyState] r => Sem r CMD.RetCode
cmdHelp = do
  -- TODO display help / use trace instead
  trace $ show $ parserHelp defaultParserPrefs mainParser
  return CMD.Continue

-- |Command specific to plots
-- TODO these should return a plot instead of a generated file so that one can overwrite the title
runPlotCommand :: (Members '[Log, Cache, P.Trace, P.State MyState, P.Embed IO] r)
  => PlotSettings -> ArgsPlots
  -> Sem r CMD.RetCode
runPlotCommand (PlotSettings mbOut _mbTitle displayPlot mptcpPlot) specificArgs = do
    (tempPath, handle) <- P.embed $ openTempFile "/tmp" "plot.png"
    _ <- case specificArgs of
      (ArgsPlotTcpAttr pcapFilename streamId attr mbDest) -> do
        let destinations = getDests mbDest
        Log.debug $ "MPTCP plot" <> tshow mptcpPlot

        res <- if mptcpPlot then do
              eFrame <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcapFilename (StreamId streamId)
              case eFrame of
                Left err -> return $ CMD.Error err
                Right frame -> Plots.cmdPlotMptcpAttribute attr tempPath handle destinations frame

            else do
              eFrame <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcapFilename (StreamId streamId)
              case eFrame of
                Left err -> return $ CMD.Error err
                Right frame -> Plots.cmdPlotTcpAttribute attr tempPath handle destinations frame
        return res

      -- Destinations
      (ArgsPlotOwdTcp mapping dest) ->
        -- Log.info $ "plotting owd for tcp.stream " <> tshow streamId1 <> " and " <> tshow streamId2
        -- eframe1 <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap1 streamId1
        -- eframe2 <- buildAFrameFromStreamIdTcp defaultTsharkPrefs pcap2 streamId2

        -- res <- case (eframe1, eframe2 ) of
        --   (Right (FrameTcp con frame1), Right aframe2) -> do
        --       -- TODO addTcpDest -> convert then
        --       let
        --         dest = genTcpDestFrame frame1 con

        --         convertCols' :: Record '[TcpDest] -> Record '[SenderDest]
        --         convertCols' = F.withNames . F.stripNames
        --         sendFrame = fmap convertCols' dest

        --       mergedRes <- mergeTcpConnectionsFromKnownStreams (FrameTcp con (F.zipFrames sendFrame frame1)) aframe2
        --       -- let mbRecs = map recMaybe mergedRes
        --       -- let justRecs = catMaybes mbRecs
        --       Plots.cmdPlotTcpOwd tempPath handle (getDests dest) (ffCon aframe1) mergedRes
        --   (Left err, _) -> return $ CMD.Error err
        --   (_, Left err) -> return $ CMD.Error err
        Plots.cmdPlotTcpOwd tempPath handle (getDests dest) mapping

      (ArgsPlotOwdMptcp (PcapMapping pcap1 streamId1 pcap2 streamId2) dest) -> do
        Log.info "plotting mptcp owd"
        eframe1 <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap1 streamId1
        eframe2 <- buildAFrameFromStreamIdMptcp defaultTsharkPrefs pcap2 streamId2

        res <- case (eframe1, eframe2 ) of
          (Right aframe1, Right aframe2) -> do
              mergedRes <- mergeMptcpConnectionsFromKnownStreams aframe1 aframe2
              -- let mbRecs = map recMaybe mergedRes
              -- let justRecs = catMaybes mbRecs
              -- Plots.cmdPlotMptcpOwd tempPath handle (getDests dest) (ffCon aframe1) mergedRes
              error "not implemented"
          (Left err, _) -> return $ CMD.Error err
          (_, Left err) -> return $ CMD.Error err
        return res


    _ <- P.embed $ case mbOut of
            -- user specified a file move the file
            Just outFilename -> renameFile tempPath outFilename
            Nothing -> return ()
    if displayPlot then do
        let
          createProc :: CreateProcess
          createProc = proc "xdg-open" [ tempPath ]

        Log.info $ "Launching " <> tshow createProc
        (_, _, mbHerr, ph) <- P.embed $ createProcess createProc
        exitCode <- P.embed $ waitForProcess ph
        return Continue

    else
      return Continue
    where
      getDests mbDest = maybe [RoleClient, RoleServer] (\x -> [x]) mbDest


-- TODO use genericRunCommand
runIteration :: ( Members '[Log, Cache, P.Trace, P.State MyState, P.Embed IO] r)
  => Maybe String
  -> Sem r CMD.RetCode
runIteration fullCmd = do
    cmdCode <- case fmap Prelude.words fullCmd of
        Nothing -> do
          trace "please enter a valid command, see help"
          return CMD.Continue
        Just args -> do
          -- TODO parse
          Log.info $ "Running " <> tshow args
          let parserResult = execParserPure defaultParserPrefs mainParserInfo args
          case parserResult of
            -- Failure (ParserFailure ParserHelp)
            (Failure failure) -> do
                -- last arg is progname
                let (h, exit) = renderFailure failure ""
                -- Log.debug h
                P.trace $ h
                Log.debug $ "Exit code " <> tshow exit
                Log.debug $ "Passed args " <> tshow args
                return $ case exit of
                    ExitSuccess -> CMD.Continue
                    ExitFailure _exitCode -> CMD.Error $ "could not parse: " ++ show failure
            (CompletionInvoked _compl) -> return CMD.Continue
            (Success parsedArgs) -> runCommand parsedArgs

    -- TODO no
    case cmdCode of
        CMD.Exit -> P.trace "Exiting" >> return CMD.Exit
        CMD.Error msg -> do
          P.trace $ "CmdCode: Last command failed with message:\n" ++ show msg
          return $ CMD.Error msg
        behavior -> return behavior

-- | Main loop of the program, will run commands in turn
inputLoop :: (Members '[Log , Cache, P.Trace, P.State MyState, P.Embed IO, P.Final (InputT IO)] r)
    => [String] -> Sem r ()
-- inputLoop (xs:rest) = pure ()
inputLoop = go
  where
    go :: (Members '[Log, Cache, P.Trace, P.State MyState, P.Embed IO, P.Final (InputT IO)] r)
      => [String] -> Sem r ()
    go (xs:rest) = runIteration (Just xs) >>= \case
        CMD.Exit -> trace "Exiting"
        _ -> do
          inputLoop rest
    go [] = do
      s <- P.get
      minput <- P.embedFinal $ getInputLine (view prompt s)
      runIteration minput >>= \case
        CMD.Exit -> trace "Exiting"
        -- _ -> pure ()
        _ -> inputLoop []

