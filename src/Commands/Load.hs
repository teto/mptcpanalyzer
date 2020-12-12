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
import Katip
import Control.Monad.Trans (MonadIO, liftIO)
-- import Control.Monad.State (get, put)
import Control.Lens hiding (argument)

import Cache
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Exit
import Utils
import Mptcp.Logging (logInfo)
-- import System.Environment (withProgName)


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
loadPcap :: CMD.CommandCb m
loadPcap args = do
    logInfo "Called loadPcap"
    -- s <- gets
    -- liftIO $ withProgName "load" (
    -- TODO fix the name of the program, by "load"
    let parserResult = execParserPure defaultParserPrefs loadOpts args
    _ <- case parserResult of
      (Failure failure) -> logInfo failure >> return ( CMD.Error "could not parse")
      -- TODO here we should complete autocompletion
      (CompletionInvoked _compl) -> return CMD.Continue
      (Success parsedArgs) -> do
          -- parsedArgs <- liftIO $ myHandleParseResult parserResult
          mFrame <- loadPcapIntoFrame defaultTsharkPrefs (pcap parsedArgs)
          -- fmap onSuccess mFrame
          case mFrame of
            Nothing -> return CMD.Continue
            Just _frame -> do
              prompt .= pcap parsedArgs ++ "> "
              loadedFile .= mFrame

              liftIO $ putStrLn "Frame loaded" >> return CMD.Continue
    return CMD.Continue

-- TODO return an Either or Maybe ?
loadPcapIntoFrame :: (Cache m, MonadIO m, KatipContext m) => TsharkParams -> FilePath -> m (Maybe PcapFrame)
loadPcapIntoFrame params path = do
    logInfo ("Start loading pcap " ++ show path)
    x <- liftIO $ getCache cacheId
    case x of
      Right frame -> do
          $(logTM) DebugS "Frame in cache"
          return $ Just frame
      Left err -> do
          liftIO $ putStrLn $ "getCache error: " ++ show err
          $(logTM) InfoS "Calling tshark"
          -- TODO need to create a temporary file
          -- mkstemps
          -- TODO use showCommandForUser to display the run command to the user
          -- , stdOut, stdErr)
          (tempPath , exitCode, stdErr) <- liftIO $ withTempFileEx opts "/tmp" "mptcp.csv" (exportToCsv params path)
          if exitCode == ExitSuccess
              then do
                $(logTM) InfoS $ logStr $ "exported to file " ++ show tempPath
                frame <- liftIO $ loadRows tempPath
                liftIO $ putStrLn $ "Number of rows after loading " ++ show (frameLength frame)
                cacheRes <- putCache cacheId tempPath
                -- use ifThenElse instead
                if cacheRes then
                  $(logTM) InfoS "Saved into cache"
                else
                  pure ()

                return $ Just frame
              else do
                let msg = "Error happened: " ++ show exitCode
                $(logTM) InfoS $ logStr msg
                -- let stdErr = "TODO"
                $(logTM) WarningS $ logStr (stdErr :: String)
                liftIO $ putStrLn "error happened: exitCode"
                return Nothing

    where
      cacheId = CacheId [path] "" ""
      opts :: TempFileOptions
      opts = TempFileOptions True

-- TODO should disappear after testing phase
loadCsv :: CMD.CommandCb m
loadCsv args = do
    logInfo "Called loadCsv"
    let parserResult = execParserPure defaultParserPrefs loadOpts args
    _ <- case parserResult of
      (Failure failure) -> logInfo failure >> return ( CMD.Error "could not load csv")
      -- TODO here we should complete autocompletion
      (CompletionInvoked _compl) -> return CMD.Continue
      (Success parsedArgs) -> do

          logInfo $ "Loading " ++ csvFilename
          -- parsedArgs <- liftIO $ myHandleParseResult parserResult
          frame <- liftIO $ loadRows csvFilename
          loadedFile .= Just frame
          logInfo $ "Number of rows " ++ show (frameLength frame)
          logInfo "Frame loaded" >> return CMD.Continue
          where
            csvFilename = pcap parsedArgs
    return CMD.Continue

-- loadRows :: IO (PcapFrame)
-- loadRows = inCoreAoS (readTable "data/server_2_filtered.pcapng.csv")

