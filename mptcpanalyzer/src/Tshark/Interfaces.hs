{-|
Module      : Tshark.Interfaces
Description : List host interfaces
Maintainer  : matt
License     : GPL-3
-}
module Tshark.Interfaces (
  listInterfaces
)
where

import Polysemy
import Polysemy.Embed
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log
import System.Exit
import System.IO
import System.Process


-- listInterfaces :: (Members [Log, Embed IO ] m) => Sem m (ExitCode, [String])
-- | List network interfaces (just their names) that are visible by tshark
listInterfaces :: IO (ExitCode, [String])
listInterfaces =
    -- defaultTsharkPrefs
    let
      (RawCommand bin args) = (RawCommand "tshark" [ "--list-interfaces" ])
      createProc :: CreateProcess
      createProc = (proc bin args) { std_out = CreatePipe }
    in do
      (_, mbHout, _mbHerr, ph) <- createProcess_ "error" createProc
      exitCode <- waitForProcess ph
      -- TODO do it only in case of error ?
      case mbHout of
        Nothing -> error "no out"
        Just hout -> do
          out <- hGetContents hout
          -- err <- hGetContents herr
          return (exitCode, map (head. tail . words) (lines out))

