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

module Main where

import System.Directory
import System.IO (stdout)
import Prelude hiding (concat, init)
import Options.Applicative
-- hiding (value, ErrorMsg, empty)
-- import qualified Options.Applicative (value)
-- import Options.Applicative.Types
import Control.Monad.Trans (liftIO, MonadIO)
-- .Strict
import Control.Monad.Trans.State (State, put,
      StateT(..),
      execStateT, runStateT, evalStateT, withStateT
        )
import Control.Monad.State (MonadState, get
    -- , StateT
    )

-- defines MonadState
-- import Control.Monad.State.Class
-- defines State
-- for noCompletion
-- import System.Console.Haskeline.Completion
import Data.List (isPrefixOf)
import System.Process
import System.Exit
import Data.Singletons.TH
import Data.Word
import Frames.TH
-- import Control.Lens hiding (Identity, argument)
-- import Data.Word (Word32)
-- import Debug.Trace

import System.Console.Haskeline
import System.Console.Haskeline.MonadException
-- Repline is a wrapper (suppposedly more advanced) around haskeline
-- for now we focus on the simple usecase with repline
-- import System.Console.Repline
import Katip
import Pcap
import Cache
-- (Cache,putCache,getCache, isValid, CacheId)
import Commands.Load ()
-- import System.Environment.Blank   (getEnvDefault)
import Distribution.Simple.Utils (withTempFileEx, TempFileOptions(..))
-- import Directory
import           Frames
import Pipes hiding (Proxy)
import qualified Pipes.Prelude as P
import qualified Control.Foldl as L
import qualified Data.Foldable as F

-- |Helper to pass information across functions
data MyState = MyState {
  -- socket :: MptcpSocket -- ^Socket
  -- -- ThreadId/MVar
  -- , connections :: Map.Map MptcpToken (ThreadId, MVar MptcpConnection)
  -- -- |Arguments passed to the program
  -- , cliArguments :: CLIArguments
  _cacheFolder :: FilePath

  , msKNamespace :: Namespace    -- ^Katip namespace
  , msLogEnv :: LogEnv     -- ^ Katip log env
  , msKContext   :: LogContexts

  , loadedFile   :: Maybe PcapFrame  -- ^ cached loaded pcap

}

newtype MyStack m a = MyStack {
    unAppT :: StateT MyState m a
} deriving (Monad, Applicative, Functor
    , MonadIO
    -- , Katip, KatipContext
    , Cache
    -- , MonadReader MyState m
    , MonadState MyState
    -- , MonadException
    )

-- (MonadState MyState m, MonadIO m) =>
-- instance (Cache AppM) where
--   putCache id frame = return False
--   getCache id = Left "not implemented"
--   -- check
--   isValid = cacheCheckValidity
-- MonadBase, MonadTransControl, and MonadBaseControl aren't strictly
-- needed for this example, but they are commonly required and
-- MonadTransControl/MonadBaseControl are a pain to implement, so I've
-- included them. Note that KatipT and KatipContextT already do this work for you.
-- instance MonadBase b m => MonadBase b (MyStack m) where
--   liftBase = liftBaseDefault


-- instance MonadTransControl MyStack where
--   -- type StT MyStack a = StT (StateT Int) a
--   type StT MyStack a = StT (ReaderT Int) a

--   liftWith = defaultLiftWith MyStack unStack
--   restoreT = defaultRestoreT MyStack


-- instance MonadBaseControl b m => MonadBaseControl b (MyStack m) where
--   type StM (MyStack m) a = ComposeSt MyStack m a
--   liftBaseWith = defaultLiftBaseWith
--   restoreM = defaultRestoreM


instance (MonadIO m, MonadState MyState (MyStack m)) => Katip (MyStack m) where
  getLogEnv = do
      s <- get
      return $ msLogEnv s
  -- (LogEnv -> LogEnv) -> m a -> m a
  localLogEnv f (MyStack m) = MyStack (withStateT (\s -> s { msLogEnv = f (msLogEnv s)}) m)

instance (MonadState MyState (MyStack m), Katip (MyStack m)) => KatipContext (MyStack m) where
  getKatipContext = do
      s <- get
      return $ msKContext s
  localKatipContext f (MyStack m) = MyStack (withStateT (\s -> s { msKContext = f (msKContext s)}) m)
  -- local (\s -> s { msKContext = f (msKContext s)}) m)
  getKatipNamespace = get >>= \x -> return $ msKNamespace x
  localKatipNamespace f (MyStack m) = MyStack (withStateT (\s -> s { msKNamespace = f (msKNamespace s)}) m)


cacheCheckValidity :: CacheId -> MyStack IO Bool
cacheCheckValidity cid = return False



instance Cache IO where
    getCache = doGetCache
    putCache = doPutCache
    isValid = isCacheValid

doGetCache :: CacheId -> IO (Either String PcapFrame)
doGetCache cid = return $ Left "getCache not implemented yet"

doPutCache :: CacheId -> FilePath -> IO Bool
doPutCache = undefined

isCacheValid :: CacheId -> IO Bool
isCacheValid  _ = return $ False

data CLIArguments = CLIArguments {

  -- | Path to a program in charge of generating congestion window limits on a 
  -- per path basis
  -- The program will be called with a json file as input and must echo on stdout
  -- an array of the form [ 10, 30, 40]
  _input :: Maybe FilePath

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



-- cmdLoadPcap :: [String] -> Repl ()
-- cmdLoadPcap args = do
--   return ()

loadCsv :: (Cache m, MonadIO m, KatipContext m) => FilePath -> m PcapFrame
loadCsv csvFile = do
    frame <- liftIO $ loadRows csvFile
    return frame

-- TODO return an Either or Maybe ?
loadPcap :: (Cache m, MonadIO m, KatipContext m) => TsharkParams -> FilePath -> m (Maybe PcapFrame)
loadPcap params path = do
    $(logTM) DebugS $ logStr ("Start loading pcap " ++ show path)
    x <- liftIO $ getCache cacheId
    case x of
      Right frame -> do
          $(logTM) DebugS $ "Frame in cache"
          return $ Just frame
      Left err -> do
          liftIO $ putStrLn $ "getCache error: " ++ show err
          $(logTM) InfoS $ "Calling tshark"
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

-- just for testing, to remove afterwards
defaultPcap :: FilePath
defaultPcap = "examples/client_2_filtered.pcapng"

instance MonadException m => MonadException (StateT s m) where
    controlIO f = StateT $ \s -> controlIO $ \(RunIO run) -> let
                    run' = RunIO (fmap (StateT . const) . run . flip runStateT s)
                    in fmap (flip runStateT s) $ f run'

main :: IO ()
main = do

  cacheFolder <- getXdgDirectory XdgCache "mptcpanalyzer"
  -- Create cache if doesn't exist
  doesDirectoryExist cacheFolder >>= \x -> case x of
      True -> putStrLn ("cache folder already exists" ++ show cacheFolder)
      False -> createDirectory cacheFolder

  handleScribe <- mkHandleScribe ColorIfTerminal stdout (permitItem DebugS) V1
  katipEnv <- initLogEnv "mptcpanalyzer" "devel"
  mkLogEnv <- registerScribe "stdout" handleScribe defaultScribeSettings katipEnv
  let myState = MyState {
    _cacheFolder = cacheFolder,
    msKNamespace = "devel",
    msLogEnv = mkLogEnv,
    msKContext = mempty,
    loadedFile = Nothing
  }

  -- putStrLn $ "Result " ++ show res
  -- TODO preload the pcap file if passed on
  options <- execParser opts

  -- check if file in cache else call tshark

  void $ flip evalStateT myState $ do
    (runInputT defaultSettings inputLoop)


  -- mFrame <- flip evalStateT myState $ do
  --   unAppT (loadPcap defaultTsharkPrefs defaultPcap)

  -- case mFrame of
  --   --  ++ show frame
  --   Just frame ->  do
  --       putStrLn $ "show frame"
  --       listTcpConnections frame
  --   Nothing -> putStrLn "frame not loaded"

  putStrLn "Thanks for flying with mptcpanalyzer"

-- 
type MptcpAnalyzer m = (Cache m, MonadIO m, KatipContext m, MonadException m, MonadState MyState m)

-- TODO retourner un code d'erreur plutot ?
-- see haskeline ExitCode
inputLoop :: (MptcpAnalyzer m) => InputT m ()
inputLoop = do
    minput <- getInputLine "% "
    case minput of
        Nothing -> return ()
        -- TODO parse first item
        Just "load" -> lift $ cmdLoad defaultPcap
        Just "quit" -> return ()
        Just input -> do
              outputStrLn $ "Input was: " ++ input
              inputLoop

-- TODO move commands to their own module
-- TODO it should update the loadedFile in State !
cmdLoad :: (MptcpAnalyzer m) => FilePath -> m ()
cmdLoad pcapFile = do
    mFrame <- loadPcap defaultTsharkPrefs pcapFile
    return ()

-- type TcpStreamT = "tcpstream" :-> Word32

listTcpConnections :: PcapFrame -> IO ()
listTcpConnections frame = do
  putStrLn "Listing tcp connections"
  let streamIds = getTcpStream frame
  mapM_ (\x -> putStrLn $ show x) streamIds
  -- L.fold L.minimum (view age <$> ms)
  -- L.fold
  -- putStrLn $ show $ rcast @'[TcpStream] $ frameRow frame 0
  -- let l =  L.fold L.nub (view tcpstream <$> frame)
  return ()

-- AppM PcapFrame
listMptcpConnections :: PcapFrame -> MyStack IO ()
listMptcpConnections frame = do
    return ()
    -- putStrLn "New frame"
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

-- mainTest :: String
-- mainTest =
--       handleRes result
--     where
--         result = execParserPure parserPrefs parserInfo cmdArgs
--         parserPrefs = defaultPrefs
--         -- "test"
--         cmdArgs = [ "mama", "--hello=toto"  ]
--         parserInfo = info simpleParser fullDesc
--         handleRes :: ParserResult SimpleData -> String
--         handleRes (CompletionInvoked compl) = "toto"
--         handleRes (Failure failure) = "failed"
--         handleRes (Success x) = "Success"


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


