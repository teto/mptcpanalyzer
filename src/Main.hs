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
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE ConstraintKinds #-}
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

import System.FilePath
import System.Directory
import System.IO (stdout)
import Prelude hiding (concat, init)
import Options.Applicative
-- import Control.Monad.Trans (liftIO, MonadIO)
-- import Control.Monad.Trans.State (StateT(..), runStateT, withStateT)
import Control.Monad.Catch
import Control.Monad.State (StateT(..), runStateT, withStateT, MonadState, gets, get)
import qualified Data.Map         as HM
import qualified Commands.Utils (RetCode(..), CommandCb)
import Commands.List

import Polysemy (Sem, Member, Members)
import qualified Polysemy as S
import Polysemy.Reader()
import qualified Polysemy.State as S
-- import qualified Polysemy.IO as S
-- import qualified Polysemy.Output as S
-- import qualified Polysemy.Trace as S

import Logging (Log, logInfo)

-- for noCompletion
import System.Console.Haskeline
-- import Data.List (isPrefixOf)
-- import Data.Singletons.TH
import Utils
import Control.Lens ( (^.), view, set)

-- Repline is a wrapper (suppposedly more advanced) around haskeline
-- for now we focus on the simple usecase with repline
-- import System.Console.Repline
import Katip
import Pcap ()
import Cache
-- (Cache,putCache,getCache, isValid, CacheId)
import Commands.Load
-- import System.Environment.Blank   (getEnvDefault)
-- import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
-- import           Frames
import Pipes hiding (Proxy)
-- import qualified Pipes.Prelude as P
-- import qualified Control.Foldl as L
-- import qualified Data.Foldable as F


newtype MyStack m a = MyStack {
    unAppT :: StateT MyState m a
} deriving (Monad, Applicative, Functor
    , MonadIO
    -- , Katip, KatipContext
    , Cache
    -- , MonadReader MyState m
    , MonadState MyState
    , MonadThrow
    , MonadCatch
    , MonadMask
    )

-- (MonadState MyState m, MonadIO m) =>
-- instance (Cache AppM) where
--   putCache id frame = return False
--   getCache id = Left "not implemented"
--   -- check
--   isValid = cacheCheckValidity

-- instance MonadBaseControl b m => MonadBaseControl b (MyStack m) where
--   type StM (MyStack m) a = ComposeSt MyStack m a
--   liftBaseWith = defaultLiftBaseWith
--   restoreM = defaultRestoreM


-- data Cache m a where
--   LogInfo :: String -> Log m ()

-- instance (MonadIO m, MonadState MyState (MyStack m)) => Katip (MyStack m) where
--   getLogEnv = do
--       s <- get
--       return $ s ^. msLogEnv
--   -- (LogEnv -> LogEnv) -> m a -> m a
--   localLogEnv f (MyStack m) = MyStack (withStateT (\s -> set msLogEnv (f (s ^. msLogEnv)) s) m)

-- instance (MonadState MyState (MyStack m), Katip (MyStack m)) => KatipContext (MyStack m) where
--   getKatipContext = do gets (view msKContext)
--   localKatipContext f (MyStack m) = MyStack (withStateT (\s -> set msKContext (f (s ^. msKContext )) s) m)
--   -- local (\s -> s { msKContext = f (msKContext s)}) m)
--   getKatipNamespace = get >>= \x -> return $ x ^. msKNamespace
--   localKatipNamespace f (MyStack m) = MyStack (withStateT (\s -> set msKNamespace (f (view msKNamespace s)) s) m)


-- cacheCheckValidity :: CacheId -> MyStack IO Bool
-- cacheCheckValidity _cid = return False


data CLIArguments = CLIArguments {
  _input :: Maybe FilePath
  , version    :: Bool  -- ^ to show version
  , cacheDir    :: Maybe FilePath -- ^ Folder where to log files
  , logLevel :: Severity   -- ^ what level to use to parse
  , extraCommands :: [String]  -- ^ commands to run on start
  }


loggerName :: String
loggerName = "main"


data Sample = Sample
  { hello      :: String
  , quiet      :: Bool
  , enthusiasm :: Int }


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
-- generateCompleter :: MonadIO m => Parser a -> CompletionFunc m
-- generateCompleter (NilP _) = noCompletion
-- -- mapParser looks cool
-- -- OpT should have optProps and optMain
-- -- en fait c'est le optReader qui va decider de tout
-- -- todo we should react depending on ParseError
-- -- CompletionResult
-- generateCompleter (OptP opt) = noCompletion

sample :: Parser CLIArguments
sample = CLIArguments
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
         <> Options.Applicative.value InfoS
         <> metavar "LOG_LEVEL" )
      -- optional arguments
      <*> some ( argument str (
            metavar "COMMANDS..."
        ))


opts :: ParserInfo CLIArguments
opts = info (sample <**> helper)
  ( fullDesc
  <> progDesc "Tool to provide insight in MPTCP (Multipath Transmission Control Protocol)\
              \performance via the generation of stats & plots"
  <> header "hello - a test for optparse-applicative"
  <> footer "You can report issues/contribute at https://github.com/teto/mptcpanalyzer"
  )

-- https://github.com/sdiehl/repline/issues/32
-- data Parser a
--   = NilP (Maybe a)
--   | OptP (Option a)
--   | forall x . MultP (Parser (x -> a)) (Parser x)
--   | AltP (Parser a) (Parser a)
--   | forall x . BindP (Parser x) (x -> Parser a)

-- TODO change
-- type Repl a = HaskelineT IO a

-- ini :: Repl ()
-- ini = liftIO $ putStrLn "Welcome!"

-- -- Commands
-- mainHelp :: [String] -> Repl ()
-- mainHelp args = liftIO $ print $ "Help: " ++ show args

-- say :: [String] -> Repl ()
-- say args = do
--   _ <- liftIO $ system $ "cowsay" ++ " " ++ (unwords args)
--   return ()

-- options :: [(String, [String] -> Repl ())]
-- options = [
--     ("help", mainHelp)  -- :help
--   , ("say", say)    -- :say
--   , ("load", cmdLoadPcap)    -- :say
--   ]
-- repl :: IO ()
-- repl = evalRepl (pure ">>> ") cmd options Nothing (Word completer) ini
-- Evaluation : handle each line user inputs

-- cmd :: String -> Repl ()
-- cmd input = liftIO $ print input

-- -- Tab Completion: return a completion for partial words entered
-- completer :: Monad m => WordCompleter m
-- completer n = do
--   let names = ["load", "listConnections", "listMptcpConnections"]
--   return $ filter (isPrefixOf n) names

-- data CompleterStyle m , I can use a Custom one
-- mainRepline :: IO ()
-- mainRepline = evalRepl (pure ">>> ") cmd Main.options Nothing (Word Main.completer) ini



-- loadCsv :: (Cache m, MonadIO m, KatipContext m) => FilePath -> m PcapFrame
-- loadCsv csvFile = do
--     frame <- liftIO $ loadRows csvFile
--     return frame


-- just for testing, to remove afterwards
defaultPcap :: FilePath
defaultPcap = "examples/client_2_filtered.pcapng"

-- instance MonadMask m => MonadMask (StateT s m) where
--     controlIO f = StateT $ \s -> controlIO $ \(RunIO run) -> let
--                     run' = RunIO (fmap (StateT . const) . run . flip runStateT s)
--                     in fmap (flip runStateT s) $ f run'

promptSuffix :: String
promptSuffix = "> "

main :: IO ()
main = do

  cacheFolderXdg <- getXdgDirectory XdgCache "mptcpanalyzer2"
  -- TODO check if creation fails ?
  -- Create cache if doesn't exist
  doesDirectoryExist cacheFolderXdg >>= \case
      True -> putStrLn ("cache folder already exists" ++ show cacheFolderXdg)
      False -> createDirectory cacheFolderXdg

  handleScribe <- mkHandleScribe ColorIfTerminal stdout (permitItem DebugS) V0
  katipEnv <- initLogEnv "mptcpanalyzer" "devel"
  mkLogEnv <- registerScribe "stdout" handleScribe defaultScribeSettings katipEnv

  let myState = MyState {
    _cacheFolder = cacheFolderXdg,
    _msKNamespace = "devel",
    _msLogEnv = mkLogEnv,
    _msKContext = mempty,
    _loadedFile = Nothing,
    _prompt = promptSuffix
  }

  options <- execParser opts

  putStrLn "Commands"
  print $ extraCommands options
  -- _ <- flip runStateT myState $ do
  --     unAppT map runCommand (extraCommands options)

  -- discards result
  -- _ <- flip runStateT myState $ do
  --     let haskelineSettings = defaultSettings {
  --         historyFile = Just $ cacheFolderXdg </> "history"
  --         }
  --     unAppT (runInputT haskelineSettings inputLoop)
  let haskelineSettings = defaultSettings {
      historyFile = Just $ cacheFolderXdg </> "history"
      }
  runInputT haskelineSettings inputLoop

  putStrLn "Thanks for flying with mptcpanalyzer"


-- TODO associate parser ?
commands :: HM.Map String CommandCb
commands = HM.fromList [
    ("load", loadPcap)
    , ("load_csv", loadCsv)
    , ("list_tcp", listTcpConnections)
    , ("help", printHelp)
    -- , ("list_mptcp", listMpTcpConnections)
    ]


-- (CMD.CommandConstraint m) => [String] -> Sem m CMD.RetCode
printHelp :: CommandCb
printHelp _ = liftIO $ putStrLn getHelp >> return CMD.Continue

getHelp :: String
getHelp =
    HM.foldrWithKey printCmdHelp "Available commands:\n" commands
    -- foldr printCmdHelp "Available commands:\n" commands
    -- foldMap
  where
    printCmdHelp k _ accum = accum ++ "\n- " ++ k

-- liftIO $ putStrLn doPrintHelp >> 

-- | Main loop of the program, will run commands in turn
-- TODO pass a dict of command ? that will parse
-- TODO turn it into a library
-- TODO embed InputT
inputLoop :: Members [S.State MyState , Log ] r => InputT (Sem r) ()
inputLoop = do
  -- todo use forever ?
    s <- lift get
    minput <- getInputLine (view prompt s)
    cmdCode <- case fmap words minput of
        Nothing -> do
          logInfo "please enter a valid command, see help"
          return CMD.Continue
        Just args -> runCommand args

    case cmdCode of
        CMD.Exit -> return ()
        CMD.Error _msg -> do
          -- lift $ putStrLn $ "Last command failed with message:\n" ++ show msg
          inputLoop
        _behavior -> inputLoop


runCommand :: Members [ S.State MyState, Log] r => [String] -> Sem r CMD.RetCode
runCommand args = do
    -- cmdCode :: CMD.RetCode
    case args of
        [] -> return CMD.Continue
        fullCmd -> do
          let commandStr = head fullCmd
          let cmd = HM.lookup commandStr commands
          case cmd of
              Nothing -> logInfo ("Unknown command " ++ commandStr) >> return CMD.Continue
              Just callback -> callback $ tail fullCmd


data SimpleData = SimpleData {
      mainStr :: String
      , optionalHello      :: String
    }

-- simpleParser :: Parser SimpleData
-- simpleParser = SimpleData
--       -- action "filepath"
--       <$> argument str (metavar "NAME" <> completeWith ["toto", "tata"])
--       <*> strOption
--           ( long "hello"
--          <> metavar "TARGET"
--          <> help "Target for the greeting" )

