{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
module Commands.Utils
where

-- import Katip
-- import Cache
-- import Control.Monad.State (MonadState)
-- import Control.Monad.Trans (MonadIO)
-- import System.Console.Haskeline.MonadException
import Utils
import Data.Text
import Polysemy
import Logging

import qualified Polysemy.State as P

data RetCode = Exit | Error Text | Continue

-- MonadException m,
-- type CommandConstraint m = (Cache m, MonadIO m, KatipContext m, MonadState MyState m)
type CommandConstraint m = Members [Log, P.State MyState  ] m

-- shouldnot modify state
type CommandCb m = CommandConstraint m => [String] -> Sem m RetCode
