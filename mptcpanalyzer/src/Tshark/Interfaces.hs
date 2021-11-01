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

import           System.IO
import           System.Process
import           System.Exit
import Polysemy
import Polysemy.Log (Log)
import Polysemy.Embed
import qualified Polysemy.Log as Log


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
      (_, mbHout, mbHerr, ph) <- createProcess_ "error" createProc
      exitCode <-waitForProcess ph
      -- TODO do it only in case of error ?
      case mbHout of
        Nothing -> error "no out"
        Just hout -> do
          out <- hGetContents hout
          -- err <- hGetContents herr
          return (exitCode, map (head. tail . words) (lines out))
      -- return (words out)
      -- return (exitCode, err)
    -- p = re.compile(r'\d. (\w+)')
    -- res = p.findall(out.decode())

