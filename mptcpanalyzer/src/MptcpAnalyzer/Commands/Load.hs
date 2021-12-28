{-|
Module: MptcpAnalyzer.Commands.Load
Maintainer  : matt
License     : GPL-3
-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
module MptcpAnalyzer.Commands.Load (
    cmdLoadCsv
  , piLoadCsv
  , piLoadPcapOpts
  , filenameReader
)
where
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Commands.Definitions as CMD
import MptcpAnalyzer.Loader
import MptcpAnalyzer.Pcap
import MptcpAnalyzer.Types
import MptcpAnalyzer.Utils.Completion (completePath, readFilename)
import MptcpAnalyzer.Utils.Text

-- import Control.Lens hiding (argument)

import Control.Monad.Trans (liftIO)
import Distribution.Simple.Utils (TempFileOptions(..), withTempFileEx)
import Frames
import Options.Applicative
import System.Exit (ExitCode(..))
-- import Prelude hiding (log)
import Options.Applicative.Builder (allPositional)
import Polysemy (Embed, Members, Sem)
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import qualified Polysemy.State as P
import qualified Polysemy.Trace as P

import Control.Monad.Trans.Except
       (ExceptT(..), runExcept, runExceptT, throwE, withExcept)

filenameReader :: ReadM FilePath
filenameReader = eitherReader readFilename
-- case readFilename filename of
--   Left err -> ReadM . lift . throwE
--   Right path -> path

-- (eitherReader readFilename)
loadPcapArgs :: Parser CommandArgs
loadPcapArgs =  ArgsLoadPcap <$>
  argument filenameReader (metavar "PCAP"
    <> completer completePath
    <> help "Load a Pcap file"
  )

cmdLoadCsvArgs :: Parser CommandArgs
cmdLoadCsvArgs =  ArgsLoadCsv <$> (
    argument str (
      metavar "CSV"
      -- <> action "file"
      <> completer completePath
      <> help "Load a Csv file"
    ))
    <*> argument auto (metavar "bool"
      <> completeWith ["true", "false"]
      <> help "boolean just to test something"
    )

piLoadCsv :: ParserInfo CommandArgs
piLoadCsv = info (cmdLoadCsvArgs <**> helper)
  ( fullDesc
  <> progDesc "Load a csv file generated from wireshark"
  )

piLoadPcapOpts :: ParserInfo CommandArgs
-- <**> helper)
piLoadPcapOpts = info loadPcapArgs
  ( fullDesc
  <> progDesc "Load a pcap file via wireshark"
  <> footer "Example: load-pcap examples/client_2_filtered.pcapng"
  <> allPositional
  )


-- myHandleParseResult :: ParserResult a -> m CMD.RetCode
-- myHandleParseResult (Success a) =



-- |Load a .csv file
cmdLoadCsv :: (Members '[Log, P.Trace, P.State MyState, Cache, Embed IO] m)
    => FilePath   -- ^ csv file to load
    -> Sem m CMD.RetCode
cmdLoadCsv csvFilename  = do

    P.trace $ "Loading " ++ csvFilename
    frame <- liftIO $ loadRows csvFilename
    -- TODO restore
    -- loadedFile .= Just frame
    P.modify (\s -> s { _loadedFile = Just frame })
    Log.info $ "Number of rows " <> tshow  (frameLength frame)
    Log.debug "Frame loaded" >> return CMD.Continue

