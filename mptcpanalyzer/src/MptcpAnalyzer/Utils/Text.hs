module MptcpAnalyzer.Utils.Text (
  -- completeInitialCommand
  -- generateHaskelineCompleterFromParser
  tshow 
)
where

import qualified Data.Text as TS

tshow :: Show a => a -> TS.Text
tshow = TS.pack . Prelude.show

