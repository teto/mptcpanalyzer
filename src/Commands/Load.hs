{-# LANGUAGE DataKinds, FlexibleContexts, QuasiQuotes, TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
module Commands.Load
where
import Frames
-- import Frames.CSV
import Pcap
-- import qualified Data.HashMap.Strict         as HM
import Commands.Utils as CMD
-- import qualified Commands.Utils         as CMD
import Options.Applicative
-- import Katip
-- MonadIO,
import Control.Monad.Trans (liftIO)
-- import Control.Monad.State (get, put)
import Control.Lens hiding (argument)

import Mptcp.Cache
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Exit
import Utils
import Mptcp.Logging (Log, logInfo)
-- import System.Environment (withProgName)
import Polysemy (Sem, Members, Embed)
import Polysemy.State as P


newtype LoadPcap = LoadPcap {
  pcap :: FilePath
}

loadPcapParser :: Parser LoadPcap
loadPcapParser = LoadPcap
      -- TODO complete with filepath
      <$> argument str (metavar "PCAP" <> completeWith ["toto", "tata"]
          <> help "Target for the greeting"
      )

-- TODO factor out
loadOpts :: ParserInfo LoadPcap
loadOpts = info (loadPcapParser <**> helper)
  ( fullDesc
  <> progDesc "Tool to provide insight in MPTCP (Multipath Transmission Control Protocol)\
              \performance via the generation of stats & plots"
  <> header "hello - a test for optparse-applicative"
  <> footer "You can report issues/contribute at https://github.com/teto/mptcpanalyzer"
  )


-- myHandleParseResult :: ParserResult a -> m CMD.RetCode
-- myHandleParseResult (Success a) = 

-- TODO move commands to their own module
-- TODO it should update the loadedFile in State !
-- handleParseResult
-- loadPcap :: CMD.CommandCb m
loadPcap :: Members [Log, P.State MyState, Cache, Embed IO] m => [String] -> Sem m RetCode
loadPcap args = do
    logInfo "Called loadPcap"
    -- s <- gets
    -- liftIO $ withProgName "load" (
    -- TODO fix the name of the program, by "load"
    let parserResult = execParserPure defaultParserPrefs loadOpts args
    case parserResult of
      -- logInfo $ show failure >>
      (Failure _failure) -> return $ CMD.Error "could not parse"
      -- TODO here we should complete autocompletion
      (CompletionInvoked _compl) -> return CMD.Continue
      (Success parsedArgs) -> do
          mFrame <- loadPcapIntoFrame defaultTsharkPrefs (pcap parsedArgs)
          -- fmap onSuccess mFrame
          case mFrame of
            Nothing -> return CMD.Continue
            Just _frame -> do
              prompt .= pcap parsedArgs ++ "> "
              loadedFile .= mFrame
              logInfo "Frame loaded" >> return CMD.Continue

-- TODO return an Either or Maybe ?
-- MonadIO m, KatipContext m
  -- EmbedIO
loadPcapIntoFrame :: Members [Cache, Log, Embed IO ] m => TsharkParams -> FilePath -> Sem m (Maybe PcapFrame)
loadPcapIntoFrame params path = do
    logInfo ("Start loading pcap " ++ show path)
    x <- getCache cacheId
    case x of
      Right frame -> do
          logInfo "Frame in cache"
          return $ Just frame
      Left err -> do
          logInfo $ "getCache error: " ++ show err
          logInfo "Calling tshark"
          -- TODO need to create a temporary file
          -- mkstemps
          -- TODO use showCommandForUser to display the run command to the user
          -- , stdOut, stdErr)
          (tempPath , exitCode, stdErr) <- liftIO $ withTempFileEx opts "/tmp" "mptcp.csv" (exportToCsv params path)
          if exitCode == ExitSuccess
              then do
                logInfo $ "exported to file " ++ show tempPath
                frame <- liftIO $ loadRows tempPath
                logInfo $ "Number of rows after loading " ++ show (frameLength frame)
                cacheRes <- putCache cacheId tempPath
                -- use ifThenElse instead
                if cacheRes then
                  logInfo "Saved into cache"
                else
                  pure ()

                return $ Just frame
              else do
                let msg = "Error happened: " ++ show exitCode
                logInfo msg
                -- let stdErr = "TODO"
                logInfo (stdErr :: String)
                logInfo "error happened: exitCode"
                return Nothing

    where
      cacheId = CacheId [path] "" ""
      opts :: TempFileOptions
      opts = TempFileOptions True

-- TODO should disappear after testing phase
-- loadCsv :: CMD.CommandCb m
loadCsv :: Members [Log, P.State MyState, Cache, Embed IO ] m => [String] -> Sem m RetCode
loadCsv args = do
    logInfo "Called loadCsv"
    let parserResult = execParserPure defaultParserPrefs loadOpts args
    _ <- case parserResult of
      (Failure _failure) -> return ( CMD.Error "could not load csv")
      -- TODO here we should complete autocompletion
      (CompletionInvoked _compl) -> return CMD.Continue
      (Success parsedArgs) -> do

          logInfo $ "Loading " ++ csvFilename
          -- parsedArgs <- liftIO $ myHandleParseResult parserResult
          frame <- liftIO $ loadRows csvFilename
          -- TODO restore
          -- loadedFile .= Just frame
          logInfo $ "Number of rows " ++ show (frameLength frame)
          logInfo "Frame loaded" >> return CMD.Continue
          where
            csvFilename = pcap parsedArgs
    return CMD.Continue

