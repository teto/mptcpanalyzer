{-|
Description : Mptcpanalyzer
Maintainer  : matt
Stability   : testing
Portability : Linux

TemplateHaskell for Katip :(
-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE TemplateHaskell   #-}

module Main where

import Prelude hiding (concat, init)
import Options.Applicative hiding (value, ErrorMsg, empty)
import qualified Options.Applicative (value)
import Control.Monad.Trans (liftIO)
import Control.Monad.Trans.State (State, StateT, put, get,
        execStateT)

import Text.Read (readMaybe)
-- pack
import Data.Text ()

import Control.Monad (foldM)
import Data.Maybe (catMaybes)
import Foreign.C.Types (CInt)
-- for eOK, ePERM
import Foreign.C.Error
import System.Linux.Netlink.GeNetlink.Control
import qualified System.Linux.Netlink.Simple as NLS
import qualified System.Linux.Netlink.Route as NLR

import System.Process
import System.Exit
import Data.Word (Word32)
-- import qualified Data.Bits as Bits -- (shiftL, )
-- import Data.Bits ((.|.))
import Data.Serialize.Get (runGet)
import Data.Serialize.Put
-- import Data.Either (fromRight)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (writeFile, readFile)

import qualified Data.Map as Map
import qualified Data.Set as Set

import qualified Data.Text
import Data.Bits (Bits(..))

import Debug.Trace

import Control.Concurrent
import System.IO.Unsafe
import System.IO.Temp ()
import System.FilePath ()
import Numeric.Natural
import System.IO (stderr)
import Data.Aeson
-- to merge MptcpConnection export and Metrics
import Data.Aeson.Extra.Merge  (lodashMerge)

import Data.Aeson.Encode.Pretty (encodePretty)

-- for getEnvDefault, to get TMPDIR value.
-- we could pass it as an argument
-- import System.Environment.Blank(getEnvDefault)

-- STM = State Thread Monad ST monad
import qualified Data.HashMap.Strict as HM
-- import System.Console.Haskeline
import System.Console.Repline
import Katip

-- |Helper to pass information across functions
data MyState = MyState {
  -- socket :: MptcpSocket -- ^Socket
  -- -- ThreadId/MVar
  -- , connections :: Map.Map MptcpToken (ThreadId, MVar MptcpConnection)
  -- -- |Arguments passed to the program
  -- , cliArguments :: CLIArguments

  -- -- |Connections to accept, loaded via cli's --filter
  -- , filteredConnections :: Maybe [TcpConnection]
  msKNamespace :: Namespace    -- |Katip namespace
  , msKContext   :: LogContexts

}


data CLIArguments = CLIArguments {

  -- | Path to a program in charge of generating congestion window limits on a 
  -- per path basis
  -- The program will be called with a json file as input and must echo on stdout
  -- an array of the form [ 10, 30, 40]
  input :: Maybe FilePath

  -- | to filter
  , version    :: Bool

  -- | Folder where to log files
  , cacheDir    :: Maybe FilePath

  , logLevel :: Severity
  }


loggerName :: String
loggerName = "main"



sample :: Parser CLIArguments
sample = CLIArguments
      <$> (optional $ strOption
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
      <*> (optional $ strOption
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
         <> Options.Applicative.value InfoS
         <> metavar "LOG_LEVEL" )


opts :: ParserInfo CLIArguments
opts = info (sample <**> helper)
  ( fullDesc
  <> progDesc "Tool to provide insight in MPTCP (Multipath Transmission Control Protocol)\
              \performance via the generation of stats & plots"
  <> header "hello - a test for optparse-applicative"
  <> footer "You can report issues/contribute at https://github.com/teto/mptcpanalyzer"
  )





-- |Deal with events for already registered connections
-- Warn: MPTCP_EVENT_ESTABLISHED registers a "null" interface
-- or a list of packets to send





main :: IO ()
main = do
  let haskelineSettings = defaultSettings
  -- SETUP LOGGING (https://gist.github.com/ijt/1052896)
  -- streamHandler vs verboseStreamHandler

  -- logMsg "main" InfoS  "Parsing command line..."
  options <- execParser opts
  let logContext = mempty
  let state = (MyState "main" logContext)


  runInputT haskelineSettings loop
  where
      loop :: InputT IO ()
      loop = do
          minput <- getInputLine "% "
          case minput of
              Nothing -> return ()
              Just "quit" -> return ()
              Just input -> do
                    outputStrLn $ "Input was: " ++ input
                    loop

