module MptcpAnalyzer.Commands (
  module MptcpAnalyzer.Commands.Load
  , module MptcpAnalyzer.Commands.Export
)
where
import Polysemy (Sem, Members, interpret)
import qualified Polysemy.Embed as P
import qualified Polysemy.State as P
import Polysemy.Log (Log)
import qualified Polysemy.Log as Log

import MptcpAnalyzer.Commands.Definitions
import MptcpAnalyzer.Cache
import MptcpAnalyzer.Types
import MptcpAnalyzer.Commands.Load
import MptcpAnalyzer.Commands.Export
import qualified MptcpAnalyzer.Commands.List as CL
import qualified MptcpAnalyzer.Commands.ListMptcp as CL
import qualified MptcpAnalyzer.Commands.Plot as PL


-- data Command m a where
--   LoadCsv :: CL.ArgsLoadPcap -> Command m RetCode
  -- LoadPcap :: ArgsLoadPcap -> Command m ()
  -- PrintHelp :: ParserArgsLoadCsv -> Command m ()
-- makeSem ''Command


printHelpTemp :: Members '[Log, Cache, P.Embed IO] r => Sem r RetCode
printHelpTemp = do
  P.embed $ putStrLn "temporary help"
  return Continue
