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
import Options.Applicative
-- hiding (value, ErrorMsg, empty)
-- import qualified Options.Applicative (value)
import Options.Applicative.Types
import Control.Monad.Trans (liftIO, MonadIO)
import Control.Monad.Trans.State (State, StateT, put, get,
        execStateT)

-- for noCompletion
import System.Console.Haskeline.Completion

import Text.Read (readMaybe)
-- pack
import Data.Text ()
import Data.List (isPrefixOf)

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
import qualified Data.Aeson as JSON
-- import Data.Aeson.Encode.Pretty (encodePretty)

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


data Sample = Sample
  { hello      :: String
  , quiet      :: Bool
  , enthusiasm :: Int }

sampleDemo :: Parser Sample
sampleDemo = Sample
      <$> strOption
          ( long "hello"
         <> metavar "TARGET"
         <> help "Target for the greeting" )
      <*> switch
          ( long "quiet"
         <> short 'q'
         <> help "Whether to be quiet" )
      <*> option auto
          ( long "enthusiasm"
         <> help "How enthusiastically to greet"
         <> showDefault
         <> value 1
         <> metavar "INT" )

-- noCompletion
-- type CompletionFunc (m :: Type -> Type) = (String, String) -> m (String, [Completion])
-- https://hackage.haskell.org/package/optparse-applicative-0.15.1.0/docs/Options-Applicative.html#t:Parser
-- optparse :: MonadIO m => Parser a -> CompletionFunc m
-- completeFilename
-- listFiles
-- autocompletion for optparse
-- https://github.com/sdiehl/repline/issues/32
-- data Parser a
--   = NilP (Maybe a)
--   | OptP (Option a)
--   | forall x . MultP (Parser (x -> a)) (Parser x)
--   | AltP (Parser a) (Parser a)
--   | forall x . BindP (Parser x) (x -> Parser a)
generateCompleter :: MonadIO m => Parser a -> CompletionFunc m
generateCompleter (NilP _) = noCompletion
-- mapParser looks cool
-- OpT should have optProps and optMain
-- en fait c'est le optReader qui va decider de tout
-- todo we should react depending on ParseError
-- CompletionResult
generateCompleter (OptP opt) = noCompletion

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

-- https://github.com/sdiehl/repline/issues/32
-- data Parser a
--   = NilP (Maybe a)
--   | OptP (Option a)
--   | forall x . MultP (Parser (x -> a)) (Parser x)
--   | AltP (Parser a) (Parser a)
--   | forall x . BindP (Parser x) (x -> Parser a)

type Repl a = HaskelineT IO a

ini :: Repl ()
ini = liftIO $ putStrLn "Welcome!"

-- Commands
mainHelp :: [String] -> Repl ()
mainHelp args = liftIO $ print $ "Help: " ++ show args

say :: [String] -> Repl ()
say args = do
  _ <- liftIO $ system $ "cowsay" ++ " " ++ (unwords args)
  return ()

options :: [(String, [String] -> Repl ())]
options = [
    ("help", mainHelp)  -- :help
  , ("say", say)    -- :say
  ]
-- repl :: IO ()
-- repl = evalRepl (pure ">>> ") cmd options Nothing (Word completer) ini
-- Evaluation : handle each line user inputs

cmd :: String -> Repl ()
cmd input = liftIO $ print input

-- Tab Completion: return a completion for partial words entered
completer :: Monad m => WordCompleter m
completer n = do
  let names = ["kirk", "spock", "mccoy"]
  return $ filter (isPrefixOf n) names

-- data CompleterStyle m , I can use a Custom one
mainRepline :: IO ()
mainRepline = evalRepl (pure ">>> ") cmd Main.options Nothing (Word Main.completer) ini

main :: IO ()
-- main = mainRepline
main = do
  let res = mainTest
  putStrLn $ "Result " ++ show res
  -- return

-- optparse
-- should pass the full line -> retreive the available completions

data SimpleData = SimpleData {
      mainStr :: String
      , optionalHello      :: String
    }

simpleParser :: Parser SimpleData
simpleParser = SimpleData
      -- action "filepath"
      <$> argument str (metavar "NAME" <> completeWith ["toto", "tata"])
      <*> strOption
          ( long "hello"
         <> metavar "TARGET"
         <> help "Target for the greeting" )

--defaultPrefs :: ParserPrefs
-- ParserPrefs
-- execParserPure :: 
-- execParserPure puis on recupere le resultat ParserResult puis on affiche la completion
-- customExecParser
-- handleParseResult

-- execParserPure :: ParserPrefs       -- ^ Global preferences for this parser
--                -> ParserInfo a      -- ^ Description of the program to run
--                -> [String]          -- ^ Program arguments
--                -> ParserResult a
-- handleParseResult

-- dealWithParseResult :: ParserResult a
-- il faudrait qu'il me retourne le champ sur lequel il foire et comme ca je peux recuperer son completer
-- s'il n'a pas de completer on affiche son aide
-- on peut aussi faire un mapping entre les action bash et les completer de repline
mainTest :: String
mainTest = 
    -- case result of
      -- CompletionResult 
      handleRes result
    where
        result = execParserPure parserPrefs parserInfo cmdArgs
        parserPrefs = defaultPrefs
        -- "test"
        cmdArgs = [ "mama", "--hello=toto"  ]
        parserInfo = info simpleParser fullDesc
        handleRes :: ParserResult SimpleData -> String
        handleRes (CompletionInvoked compl) = "toto"
        handleRes (Failure failure) = "failed"
        handleRes (Success x) = "Success"


-- mainHaskeline :: IO ()
-- mainHaskeline = do
--   let haskelineSettings = defaultSettings
--   -- SETUP LOGGING (https://gist.github.com/ijt/1052896)
--   -- streamHandler vs verboseStreamHandler

--   -- logMsg "main" InfoS  "Parsing command line..."
--   options <- execParser opts
--   let logContext = mempty
--   let state = (MyState "main" logContext)


--   runInputT haskelineSettings loop
--   where
--       loop :: InputT IO ()
--       loop = do
--           minput <- getInputLine "% "
--           case minput of
--               Nothing -> return ()
--               Just "quit" -> return ()
--               Just input -> do
--                     outputStrLn $ "Input was: " ++ input
--                     loop

