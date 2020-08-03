{-# LANGUAGE DataKinds, FlexibleContexts, QuasiQuotes, TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
module Commands.Load
where
import Frames
-- import Frames.CSV
import Pcap
import           Frames.TH                      ( rowGen
                                                , RowGen(..)
                                                )
-- import qualified Data.HashMap.Strict         as HM
import qualified Commands.Utils         as CMD
import Options.Applicative
import Katip
import Control.Monad.Trans (MonadIO, liftIO)
import Cache
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
import System.Exit


data LoadPcap = LoadPcap {
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

-- TODO move commands to their own module
-- TODO it should update the loadedFile in State !
loadPcap :: (CMD.CommandConstraint m) => [String] -> m ()
loadPcap pcapFile = do
    $(logTM) DebugS $ logStr "starting"
    args <- liftIO $ execParser loadOpts
    mFrame <- loadPcapIntoFrame defaultTsharkPrefs (pcap args)
    _ <- liftIO $ putStrLn "Frame loaded"

    return ()

-- TODO return an Either or Maybe ?
loadPcapIntoFrame :: (Cache m, MonadIO m, KatipContext m) => TsharkParams -> FilePath -> m (Maybe PcapFrame)
loadPcapIntoFrame params path = do
    $(logTM) DebugS $ logStr ("Start loading pcap " ++ show path)
    x <- liftIO $ getCache cacheId
    case x of
      Right frame -> do
          $(logTM) DebugS $ logStr "Frame in cache"
          return $ Just frame
      Left err -> do
          liftIO $ putStrLn $ "getCache error: " ++ show err
          $(logTM) InfoS $ logStr "Calling tshark"
          -- TODO need to create a temporary file
          -- mkstemps
          -- TODO use showCommandForUser to display the run command to the user
          -- , stdOut, stdErr)
          (tempPath , exitCode, stdErr) <- liftIO $ withTempFileEx opts "/tmp" "mptcp.csv" (exportToCsv params path)
          if exitCode == ExitSuccess
              then do
                $(logTM) InfoS $ logStr $ "exported to file " ++ show tempPath
                frame <- liftIO $ loadRows tempPath
                liftIO $ putStrLn $ "Number of rows " ++ show (frameLength frame)
                return $ Just frame
                -- putCache cacheId
                -- TODO update the state too
                -- pass
              else do
                let msg = "Error happened: " ++ show exitCode
                $(logTM) InfoS $ logStr msg
                -- let stdErr = "TODO"
                $(logTM) WarningS $ logStr (stdErr :: String)
                -- liftIO $ putStrLn $ "error happened: exitCode" 
                -- ++ show stderr >>
                return Nothing

          -- and then the handle can be used via "export_to_csv"
          -- mkstemp
          -- withCreateProcess createProc

            -- createProcess 
            -- error "could not load pcap"

    where
      cacheId = CacheId [path] "" ""
      fields :: [String]
      fields = [
        "tcp.stream"
        ]
      opts :: TempFileOptions
      opts = TempFileOptions True


-- loadRows :: IO (PcapFrame)
-- loadRows = inCoreAoS (readTable "data/server_2_filtered.pcapng.csv")

