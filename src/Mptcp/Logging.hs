module Mptcp.Logging
where

import Polysemy

data Severity = TraceS | DebugS | InfoS | ErrorS deriving (Read, Show, Eq)

data Log m a where
  LogInfo :: String -> Log m ()

-- generates logInfo function
makeSem ''Log

logToIO :: Member (Embed IO) r => Sem (Log ': r) a -> Sem r a
logToIO = interpret (\(LogInfo stringToLog) -> embed $ putStrLn stringToLog)

